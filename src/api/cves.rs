use log::error;
use rocket::response::status::BadRequest;
use rocket_contrib::json::Json;

use crate::db::{models::CVE, Database};
use crate::search::{self, Query};

#[post("/search", format = "application/json", data = "<query>")]
pub fn search(
    query: Json<Query>,
    database: Database,
) -> Result<Json<Vec<CVE>>, BadRequest<String>> {
    match search::query(&database, &query.into_inner()) {
        Ok(v) => Ok(Json(v)),
        Err(e) => {
            error!("{}", &e);
            Err(BadRequest(Some(e)))
        }
    }
}
