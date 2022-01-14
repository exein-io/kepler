use std::collections::HashMap;

use log::error;
use rocket::http::Status;
use rocket_contrib::json::Json;

use crate::db::{models::Product, Database};

#[get("/")]
pub fn all(database: Database) -> Result<Json<Vec<Product>>, Status> {
    match database.get_products() {
        Ok(v) => Ok(Json(v)),
        Err(e) => {
            error!("{}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[get("/by_vendor")]
pub fn by_vendor(database: Database) -> Result<Json<HashMap<String, Vec<String>>>, Status> {
    match database.get_products() {
        Ok(products) => {
            let mut grouped: HashMap<String, Vec<String>> = HashMap::new();

            for prod in products {
                if let Some(group) = grouped.get_mut(&prod.vendor) {
                    group.push(prod.product.clone());
                } else {
                    grouped.insert(prod.vendor.clone(), vec![prod.product.clone()]);
                }
            }

            Ok(Json(grouped))
        }
        Err(e) => {
            error!("{}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[get("/search/<query>")]
pub fn search(
    query: &rocket::http::RawStr,
    database: Database,
) -> Result<Json<Vec<Product>>, Status> {
    match database.search_products(query.as_str()) {
        Ok(v) => Ok(Json(v)),
        Err(e) => {
            error!("{}", e);
            Err(Status::InternalServerError)
        }
    }
}
