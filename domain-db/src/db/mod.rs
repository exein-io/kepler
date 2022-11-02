use std::ops::Deref;

use anyhow::{bail, Context, Result};
use diesel::insert_into;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use r2d2_diesel::ConnectionManager;

pub mod migrations;
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
}
