use crate::search::{self, Query};
use actix_web::{web, HttpResponse};

use super::{
    error::ApplicationError,
    utils::{bad_request_body, handle_database_error, ok_to_json},
    ApplicationContext,
};

pub async fn search(
    ctx: web::Data<ApplicationContext>,
    query: web::Json<Query>,
) -> Result<HttpResponse, ApplicationError> {
    let database = ctx.get_database().map_err(handle_database_error)?;

    search::query(&database, &query.into_inner())
        .map(ok_to_json)
        .map_err(bad_request_body)
}
