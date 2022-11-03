use std::ops::Deref;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use diesel::insert_into;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use r2d2::PooledConnection;
use r2d2_diesel::ConnectionManager;

pub mod models;
pub mod schema;

use models::CVE;
use serde::Deserialize;
use version_compare::Cmp;

use crate::sources::nist;

#[derive(thiserror::Error, Debug)]
#[error("Database error.")]
pub struct DatabaseError {
    #[from]
    source: r2d2::Error,
}

pub struct PostgresRepository {
    pool: r2d2::Pool<ConnectionManager<PgConnection>>,
}

impl PostgresRepository {
    pub fn new(database_url: &str) -> Result<Self, DatabaseError> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = r2d2::Pool::new(manager)?;
        Ok(Self { pool })
    }
}

impl PostgresRepository {
    pub fn setup_database(&self) -> Result<usize> {
        let conn = self.pool.get()?;
        diesel_migrations::setup_database(&*conn).context("database setup failed")
    }

    pub fn any_pending_migrations(&self) -> Result<bool> {
        let conn = self.pool.get()?;
        diesel_migrations::any_pending_migrations(&*conn)
            .context("failed checking pending migrations")
    }

    pub fn run_pending_migrations(&self) -> Result<()> {
        let conn = self.pool.get()?;
        diesel_migrations::run_pending_migrations(&*conn)
            .context("failed runnign pending migrations")
    }

    pub fn create_object_if_not_exist(&self, values: models::NewObject) -> Result<i32> {
        use schema::objects::dsl::*;

        let conn = self.pool.get()?;

        let found = objects
            .filter(cve.eq(&values.cve))
            .first::<models::Object>(conn.deref());

        match found {
            Ok(obj) => return Ok(obj.id),
            Err(diesel::result::Error::NotFound) => {}
            Err(e) => bail!(e),
        }

        let object: models::Object = insert_into(objects)
            .values(values)
            .get_result(conn.deref())
            .context("error inserting object")?;

        Ok(object.id)
    }

    pub fn create_cve_if_not_exist(&self, values: models::NewCVE) -> Result<bool> {
        use schema::cves::dsl::*;

        let conn = self.pool.get()?;

        // check if we have it already by (vendor, product, cve)
        let found: i64 = cves
            .filter(
                vendor
                    .eq(&values.vendor)
                    .and(product.eq(&values.product))
                    .and(cve.eq(&values.cve)),
            )
            .count()
            .get_result(conn.deref())
            .context("error counting cves")?;

        if found > 0 {
            return Ok(false);
        }

        // create it as a new record
        insert_into(cves)
            .values(values)
            .execute(conn.deref())
            .context("error creating cve")?;

        Ok(true)
    }

    pub fn delete_cve(&self, the_vendor: &str, the_product: &str, the_cve: &str) -> Result<usize> {
        use schema::cves::dsl::*;

        let conn = self.pool.get()?;

        diesel::delete(
            cves.filter(
                vendor
                    .eq(the_vendor)
                    .and(product.eq(the_product))
                    .and(cve.eq(the_cve)),
            ),
        )
        .execute(conn.deref())
        .context("error deleting cve")
    }

    pub fn get_products(&self) -> Result<Vec<models::Product>> {
        use schema::cves::dsl::*;

        let conn = self.pool.get()?;

        let prods: Vec<(String, String)> = cves
            .select((vendor, product))
            .distinct()
            .get_results::<(String, String)>(conn.deref())
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

        let conn = self.pool.get()?;

        let prods: Vec<(String, String)> = cves
            .select((vendor, product))
            .distinct()
            .filter(product.like(format!("%{}%", query)))
            .get_results::<(String, String)>(conn.deref())
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

    pub fn query(&self, query: &Query, cache: Option<&dyn CveCache>) -> Result<Vec<models::CVE>> {
        log::info!("searching query: {:?} ...", query);

        // validate version string
        if version_compare::compare_to(&query.version, "1.0.0", Cmp::Ne).is_err() {
            bail!("invalid version string");
        }

        // Check the optional cache first
        if let Some(cache) = cache {
            if let Some(cached) = cache.get(query) {
                log::debug!("cache hit");
                return Ok(cached);
            } else {
                log::debug!("cache miss");
            }
        }

        let conn = self.pool.get()?;

        // fetch potential candidates for this query
        let start = Instant::now();
        let candidates = fetch_candidates(&conn, query.vendor.as_ref(), &query.product)?;
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
                    Some(cve)
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

        // Update the optional cache
        if let Some(cache) = cache {
            log::debug!("update cache");
            cache.put(query.clone(), matches.clone());
        }

        Ok(matches)
    }
}

pub trait CveCache {
    fn get(&self, query: &Query) -> Option<Vec<CVE>>;
    fn put(&self, query: Query, cves: Vec<CVE>) -> Option<Vec<CVE>>;
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct Query {
    pub vendor: Option<String>,
    pub product: String,
    pub version: String,
}

fn fetch_candidates(
    conn: &PooledConnection<ConnectionManager<PgConnection>>,
    by_vendor: Option<&String>,
    by_product: &str,
) -> Result<Vec<(models::CVE, models::Object)>> {
    use schema::cves::dsl::*;
    use schema::objects::dsl::*;

    match (by_vendor, by_product) {
        (Some(v), p) => cves
            .filter(product.eq(p).and(vendor.eq(v)))
            .inner_join(objects)
            .load(conn.deref())
            .context("error searching records"),
        (None, p) => cves
            .filter(product.eq(p))
            .inner_join(objects)
            .load(conn.deref())
            .context("error searching records"),
    }
}

#[derive(Debug, Deserialize)]
pub enum Source {
    Nist(nist::cve::item::CVE),
    // Placeholder different types
}

impl Source {
    pub fn is_match(&mut self, product: &str, version: &str) -> bool {
        match self {
            Self::Nist(cve) => cve.is_match(product, version),
        }
    }
}
