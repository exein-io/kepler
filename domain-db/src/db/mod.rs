use std::collections::HashMap;
use std::env;
use std::sync::LazyLock;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
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

/// Configured batch size for inserting objects into the database.
/// Maximum allowed size is 65535 parameters per query in PostgreSQL, so we set a default of 5000.
///
/// We can set it to maximum of about 5500 for current [`domain_db::db::NewCVE`] parameteer count.
///
/// DOCS: https://www.postgresql.org/docs/current/limits.html
pub static KEPLER_BATCH_SIZE: LazyLock<usize> = LazyLock::new(|| {
    env::var("KEPLER__BATCH_SIZE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(5000)
});

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

    /// Insert a list of objects into the database if they don't already exist.
    ///
    /// Insertion is done in batches of size `KEPLER__BATCH_SIZE` to avoid exceeding the maximum number of parameters = *(65535)* for PostgreSQL  
    ///
    /// Returns a [`HashMap<String, i32>`] of CVE IDs to their assigned object IDs.
    pub fn insert_objects(
        &self,
        objects_to_insert: Vec<models::NewObject>,
    ) -> Result<HashMap<String, i32>> {
        let mut inserted_object_ids = HashMap::new();

        if objects_to_insert.is_empty() {
            return Ok(inserted_object_ids);
        }

        for chunk in objects_to_insert.chunks(*KEPLER_BATCH_SIZE) {
            let inserted_ids: HashMap<String, i32> =
                self.batch_insert_objects(chunk)?.into_iter().collect();

            inserted_object_ids.extend(inserted_ids);
        }
        Ok(inserted_object_ids)
    }

    /// Inserts [`schema::objects`] into database in batches of size `KEPLER__BATCH_SIZE`
    pub fn batch_insert_objects(
        &self,
        values_list: &[models::NewObject],
    ) -> Result<Vec<(String, i32)>> {
        use schema::objects::dsl::*;

        let object_cves: Vec<String> = values_list.iter().map(|obj| obj.cve.clone()).collect();

        let mut conn = self.pool.get()?;
        conn.transaction(|conn| {
            let inserted_count = diesel::insert_into(objects)
                .values(values_list)
                .on_conflict(cve)
                .do_nothing()
                .execute(conn)
                .context("error creating objects in batch")?;

            if inserted_count > 0 {
                log::info!("batch imported {} object records ...", inserted_count);
            } else {
                log::warn!("Zero object records are inserted!");
            }

            let inserted_objects = objects
                .filter(cve.eq_any(&object_cves))
                .select((cve, id))
                // Query back the inserted records to get their assigned IDs
                .load(conn)
                .context("error retrieving inserted object IDs")?;

            Ok(inserted_objects)
        })
    }

    /// Batch insert CVEs if they don't already exist in the database
    ///
    /// Returns the number of inserted records
    pub fn batch_insert_cves(&self, values_list: Vec<models::NewCVE>) -> Result<usize> {
        use schema::cves::dsl::*;

        let mut conn = self.pool.get()?;
        conn.transaction(|conn| {
            let inserted_count = insert_into(cves)
                .values(&values_list)
                .on_conflict((cve, vendor, product))
                .do_nothing()
                .execute(conn)
                .context("error creating cves in batch")?;

            Ok(inserted_count)
        })
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

/// Create unique objects from the CVE list
pub fn create_unique_objects(
    cve_list: &[nist::cve::CVE],
) -> Result<HashMap<String, models::NewObject>> {
    Ok(cve_list
        .iter()
        .filter_map(|item| {
            serde_json::to_string(item).ok().map(|json| {
                let id = item.id().to_string();
                (id.clone(), models::NewObject::with(id, json))
            })
        })
        .collect())
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
