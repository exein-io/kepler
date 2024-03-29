use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use diesel::insert_into;
use diesel::migration::MigrationConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, PooledConnection};
use diesel_migrations::{FileBasedMigrations, MigrationHarness};
use serde::{Deserialize, Serialize};
use version_compare::Cmp;

use crate::cve_sources::nist;

pub mod models;
pub mod schema;

#[derive(thiserror::Error, Debug)]
#[error("Database error.")]
pub struct DatabaseError {
    #[from]
    source: r2d2::Error,
}

pub struct PostgresRepository {
    pool: r2d2::Pool<ConnectionManager<PgConnection>>,
    migrations: FileBasedMigrations,
}

impl PostgresRepository {
    pub fn new(database_url: &str, migrations_directory: &str) -> Result<Self> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = r2d2::Pool::new(manager)?;

        let migrations = FileBasedMigrations::from_path(migrations_directory)?;

        Ok(Self { pool, migrations })
    }
}

impl PostgresRepository {
    pub fn setup_database(&self) -> Result<usize> {
        let mut conn = self.pool.get()?;
        conn.setup().context("database setup failed")
    }

    pub fn any_pending_migrations(&self) -> Result<bool> {
        let mut conn = self.pool.get()?;

        conn.has_pending_migration(self.migrations.clone())
            .map_err(|e| anyhow!(e))
            .context("failed checking pending migrations")
    }

    pub fn run_pending_migrations(&self) -> Result<()> {
        let mut conn = self.pool.get()?;

        conn.run_pending_migrations(self.migrations.clone())
            .map_err(|e| anyhow!(e))
            .context("failed running pending migrations")?;

        Ok(())
    }

    pub fn create_object_if_not_exist(&self, values: models::NewObject) -> Result<i32> {
        use schema::objects::dsl::*;

        let mut conn = self.pool.get()?;

        let found = objects
            .filter(cve.eq(&values.cve))
            .first::<models::Object>(&mut conn);

        match found {
            Ok(obj) => return Ok(obj.id),
            Err(diesel::result::Error::NotFound) => {}
            Err(e) => bail!(e),
        }

        let object: models::Object = insert_into(objects)
            .values(values)
            .get_result(&mut conn)
            .context("error inserting object")?;

        Ok(object.id)
    }

    pub fn create_cve_if_not_exist(&self, values: models::NewCVE) -> Result<bool> {
        use schema::cves::dsl::*;

        let mut conn = self.pool.get()?;

        // check if we have it already by (vendor, product, cve)
        let found: i64 = cves
            .filter(
                vendor
                    .eq(&values.vendor)
                    .and(product.eq(&values.product))
                    .and(cve.eq(&values.cve)),
            )
            .count()
            .get_result(&mut conn)
            .context("error counting cves")?;

        if found > 0 {
            return Ok(false);
        }

        // create it as a new record
        insert_into(cves)
            .values(values)
            .execute(&mut conn)
            .context("error creating cve")?;

        Ok(true)
    }

    pub fn delete_cve(&self, the_vendor: &str, the_product: &str, the_cve: &str) -> Result<usize> {
        use schema::cves::dsl::*;

        let mut conn = self.pool.get()?;

        diesel::delete(
            cves.filter(
                vendor
                    .eq(the_vendor)
                    .and(product.eq(the_product))
                    .and(cve.eq(the_cve)),
            ),
        )
        .execute(&mut conn)
        .context("error deleting cve")
    }

    pub fn get_products(&self) -> Result<Vec<models::Product>> {
        use schema::cves::dsl::*;

        let mut conn = self.pool.get()?;

        let prods: Vec<(String, String)> = cves
            .select((vendor, product))
            .distinct()
            .get_results::<(String, String)>(&mut conn)
            .context("error fetching products")?;

        let products = prods
            .iter()
            .map(|(v, p)| models::Product {
                vendor: v.into(),
                product: p.into(),
            })
            .collect();

        Ok(products)
    }

    pub fn search_products(&self, query: &str) -> Result<Vec<models::Product>> {
        use schema::cves::dsl::*;

        let mut conn = self.pool.get()?;

        let prods: Vec<(String, String)> = cves
            .select((vendor, product))
            .distinct()
            .filter(product.like(format!("%{}%", query)))
            .get_results::<(String, String)>(&mut conn)
            .context("error searching products")?;

        let products = prods
            .iter()
            .map(|(v, p)| models::Product {
                vendor: v.into(),
                product: p.into(),
            })
            .collect();

        Ok(products)
    }

    pub fn query(&self, query: &Query) -> Result<Vec<MatchedCVE>> {
        log::info!("searching query: {:?} ...", query);

        // validate version string
        if version_compare::compare_to(&query.version, "1.0.0", Cmp::Ne).is_err() {
            bail!("invalid version string");
        }

        let mut conn = self.pool.get()?;

        // fetch potential candidates for this query
        let start = Instant::now();
        let candidates = fetch_candidates(&mut conn, query.vendor.as_ref(), &query.product)?;
        log::info!(
            "found {} candidates in {} ms",
            candidates.len(),
            start.elapsed().as_millis()
        );

        // deserialize all objects belonging to the potential CVEs
        let start = Instant::now();
        let sources = candidates
            .into_iter()
            .map(|(cve, obj)| match cve.source.as_str() {
                nist::SOURCE_NAME => {
                    if let Ok(cve_des) = serde_json::from_str(&obj.data) {
                        Ok((cve, Source::Nist(cve_des)))
                    } else {
                        Err(anyhow!("could not deserialize {}", obj.cve))
                    }
                }
                _ => Err(anyhow!("unsupported data source {}", cve.source)),
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;
        log::info!(
            "deserialized the {} candidates in {} ms",
            sources.len(),
            start.elapsed().as_millis()
        );

        // Find match
        let matches = sources
            .into_iter()
            .filter_map(|(cve, mut source)| {
                if source.is_match(&query.product, &query.version) {
                    let product = models::Product {
                        vendor: cve.vendor,
                        product: cve.product,
                    };

                    let matched_cve = match source {
                        Source::Nist(nist_cve) => (product, nist_cve).into(),
                    };

                    Some(matched_cve)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        log::info!(
            "found {} matches in {} ms",
            matches.len(),
            start.elapsed().as_millis()
        );

        Ok(matches)
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct Query {
    pub vendor: Option<String>,
    pub product: String,
    pub version: String,
}

fn fetch_candidates(
    conn: &mut PooledConnection<ConnectionManager<PgConnection>>,
    by_vendor: Option<&String>,
    by_product: &str,
) -> Result<Vec<(models::CVE, models::Object)>> {
    use schema::cves::dsl::*;
    use schema::objects::dsl::*;

    match (by_vendor, by_product) {
        (Some(v), p) => cves
            .filter(product.eq(p).and(vendor.eq(v)))
            .inner_join(objects)
            .load(&mut *conn)
            .context("error searching records"),
        (None, p) => cves
            .filter(product.eq(p))
            .inner_join(objects)
            .load(&mut *conn)
            .context("error searching records"),
    }
}

#[derive(Debug, Deserialize)]
pub enum Source {
    Nist(nist::cve::CVE),
    // Placeholder different types
}

impl Source {
    pub fn is_match(&mut self, product: &str, version: &str) -> bool {
        match self {
            Self::Nist(cve) => cve.is_match(product, version),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchedCVE {
    pub cve: String, // ID
    pub source: String,
    pub vendor: String,
    pub product: String,
    pub summary: Option<String>,
    pub references: Vec<Reference>,
    pub problems: Vec<String>,
    #[serde(rename = "publishedDate")] // TODO: remove after response type implementation
    pub published_date: String,
    #[serde(rename = "lastModifiedDate")] // TODO: remove after response type implementation
    pub last_modified_date: String,
    pub cvss: CVSS,
}

impl From<(models::Product, nist::cve::CVE)> for MatchedCVE {
    fn from((product, nist_cve): (models::Product, nist::cve::CVE)) -> Self {
        let references = nist_cve
            .cve
            .references
            .reference_data
            .iter()
            .map(|reference| Reference {
                url: reference.url.clone(),
                tags: reference.tags.clone(),
            })
            .collect();

        let models::Product { vendor, product } = product;

        MatchedCVE {
            cve: nist_cve.id().into(),
            source: nist::SOURCE_NAME.into(),
            vendor,
            product,
            summary: nist_cve.summary().map(str::to_string),
            references,
            problems: nist_cve
                .problems()
                .into_iter()
                .map(str::to_string)
                .collect(),
            published_date: nist_cve.published_date,
            last_modified_date: nist_cve.last_modified_date,
            cvss: CVSS {
                v3: nist_cve.impact.metric_v3.map(|metric| CVSSVData {
                    vector_string: metric.cvss.vector_string,
                    base_score: metric.cvss.base_score,
                    impact_score: metric.impact_score,
                    severity: metric.cvss.base_severity,
                }),
                v2: nist_cve.impact.metric_v2.map(|metric| CVSSVData {
                    vector_string: metric.cvss.vector_string,
                    base_score: metric.cvss.base_score,
                    impact_score: metric.impact_score,
                    severity: metric.severity,
                }),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub url: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CVSS {
    v3: Option<CVSSVData>,
    v2: Option<CVSSVData>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CVSSVData {
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    #[serde(rename = "impactScore")]
    pub impact_score: f32,
    pub severity: String,
}
