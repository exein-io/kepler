use std::ops::Deref;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use diesel::insert_into;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use r2d2_diesel::ConnectionManager;

pub mod models;
pub mod schema;

use models::CVE;
use serde::Deserialize;
use version_compare::Cmp;

use crate::sources::{nist, Source};

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

    pub fn search(
        &self,
        by_vendor: Option<&String>,
        by_product: &str,
    ) -> Result<Vec<(models::CVE, models::Object)>> {
        use schema::cves::dsl::*;
        use schema::objects::dsl::*;

        let conn = self.pool.get()?;

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
        if let Some(ver) = &query.version {
            if version_compare::compare_to(ver, "1.0.0", Cmp::Ne).is_err() {
                bail!("invalid version string");
            }
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

        // fetch potential candidates for this query
        let start = Instant::now();
        let candidates = self.search(query.vendor.as_ref(), &query.product)?;

        log::info!(
            "found {} candidates in {:?}",
            candidates.len(),
            start.elapsed()
        );

        // deserialize all objects belonging to the potential CVEs
        let start = Instant::now();
        let mut matches = vec![];
        let mut sources = vec![];

        for (cve, obj) in &candidates {
            match cve.source.as_str() {
                nist::SOURCE_NAME => {
                    if let Ok(cve) = serde_json::from_str(&obj.data) {
                        sources.push(Source::Nist(cve));
                    } else {
                        bail!("could not deserialize {}", obj.cve);
                    }
                }
                _ => bail!("unsupported data source {}", cve.source),
            }
        }

        log::info!(
            "deserialized the {} candidates in {:?}",
            sources.len(),
            start.elapsed()
        );

        let start = Instant::now();
        for (index, object) in sources.iter_mut().enumerate() {
            if let Some(version) = &query.version {
                if object.is_match(&query.product, version) {
                    matches.push(candidates[index].0.clone());
                }
            }
        }

        log::info!("found {} matches in {:?}", matches.len(), start.elapsed());

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
    pub version: Option<String>,
}
