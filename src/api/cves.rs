use crate::{
    db::models::CVE,
    search::{self, Query},
};
use actix_web::web::{self, Json};

use super::{
    error::{bad_request_body, handle_blocking_error, handle_database_error, ApplicationError},
    ApplicationContext,
};

pub async fn search(
    ctx: web::Data<ApplicationContext>,
    query: Json<Query>,
) -> Result<Json<Vec<CVE>>, ApplicationError> {
    let cves = web::block(move || {
        let database = ctx.get_database().map_err(handle_database_error)?;
        search::query(&database, &query.into_inner()).map_err(bad_request_body)
    })
    .await
    .map_err(handle_blocking_error)??;

    Ok(Json(cves))
}
