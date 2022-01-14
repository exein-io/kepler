use std::ops::Deref;

use diesel::insert_into;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use r2d2_diesel::ConnectionManager;
use rocket::http::Status;
use rocket::request::{self, FromRequest};
use rocket::{Outcome, Request, State};

pub mod models;
pub mod schema;

pub struct Database(pub r2d2::PooledConnection<ConnectionManager<PgConnection>>);

impl<'a, 'r> FromRequest<'a, 'r> for Database {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Database, Self::Error> {
        let pool = request.guard::<State<Pool>>()?;
        match pool.get() {
            Ok(conn) => Outcome::Success(Database(conn)),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ())),
        }
    }
}

impl Deref for Database {
    type Target = PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub fn setup(database_url: &str) -> Result<Pool, String> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::new(manager).map_err(|e| e.to_string())
}

impl Database {
    pub fn create_object_if_not_exist(&self, values: models::NewObject) -> Result<i32, String> {
        use schema::objects::dsl::*;

        let found = objects
            .filter(cve.eq(&values.cve))
            .first::<models::Object>(self.deref());

        match found {
            Ok(obj) => return Ok(obj.id),
            Err(diesel::result::Error::NotFound) => {}
            Err(e) => return Err(e.to_string()),
        }

        let object: models::Object = insert_into(objects)
            .values(values)
            .get_result(self.deref())
            .map_err(|e| format!("error creating record: {}", e))?;

        Ok(object.id)
    }

    pub fn create_cve_if_not_exist(&self, values: models::NewCVE) -> Result<bool, String> {
        use schema::cves::dsl::*;

        // check if we have it already by (vendor, product, cve)
        let found: i64 = cves
            .filter(
                vendor
                    .eq(&values.vendor)
                    .and(product.eq(&values.product))
                    .and(cve.eq(&values.cve)),
            )
            .count()
            .get_result(self.deref())
            .map_err(|e| format!("error counting records: {}", e))?;

        if found > 0 {
            return Ok(false);
        }

        // create it as a new record
        insert_into(cves)
            .values(values)
            .execute(self.deref())
            .map_err(|e| format!("error creating record: {}", e))?;

        Ok(true)
    }

    pub fn delete_cve(
        &self,
        the_vendor: &str,
        the_product: &str,
        the_cve: &str,
    ) -> Result<usize, String> {
        use schema::cves::dsl::*;

        diesel::delete(
            cves.filter(
                vendor
                    .eq(the_vendor)
                    .and(product.eq(the_product))
                    .and(cve.eq(the_cve)),
            ),
        )
        .execute(self.deref())
        .map_err(|e| format!("error deleting record: {}", e))
    }

    pub fn search(
        &self,
        by_vendor: Option<&String>,
        by_product: &str,
    ) -> Result<Vec<(models::CVE, models::Object)>, String> {
        use schema::cves::dsl::*;
        use schema::objects::dsl::*;

        Ok(match (by_vendor, by_product) {
            (Some(v), p) => cves
                .filter(product.eq(p).and(vendor.eq(v)))
                .inner_join(objects)
                .load(self.deref())
                .map_err(|e| format!("error searching records: {}", e))?,
            (None, p) => cves
                .filter(product.eq(p))
                .inner_join(objects)
                .load(self.deref())
                .map_err(|e| format!("error searching records: {}", e))?,
        })
    }

    pub fn get_products(&self) -> Result<Vec<models::Product>, String> {
        use schema::cves::dsl::*;

        let prods: Vec<(String, String)> = cves
            .select((vendor, product))
            .distinct()
            .get_results::<(String, String)>(self.deref())
            .map_err(|e| format!("error fetching products: {}", e))?;

        Ok(prods
            .iter()
            .map(|(v, p)| models::Product {
                vendor: v.into(),
                product: p.into(),
            })
            .collect())
    }

    pub fn search_products(&self, query: &str) -> Result<Vec<models::Product>, String> {
        use schema::cves::dsl::*;

        let prods: Vec<(String, String)> = cves
            .select((vendor, product))
            .distinct()
            .filter(product.like(format!("%{}%", query)))
            .get_results::<(String, String)>(self.deref())
            .map_err(|e| format!("error searching products: {}", e))?;

        Ok(prods
            .iter()
            .map(|(v, p)| models::Product {
                vendor: v.into(),
                product: p.into(),
            })
            .collect())
    }
}
