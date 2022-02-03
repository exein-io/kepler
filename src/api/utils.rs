use actix_web::{error::BlockingError, HttpResponse};
use serde::Serialize;

use super::error::ApplicationError;

pub fn ok_to_json<T: Serialize>(object: T) -> HttpResponse {
    HttpResponse::Ok().json(object)
}

pub fn handle_database_error(error: r2d2::Error) -> ApplicationError {
    log::error!("{}", error);
    ApplicationError::ServiceUnavailable
}

pub fn handle_blocking_error(error: BlockingError) -> ApplicationError {
    log::error!("{}", error);
    ApplicationError::ServiceUnavailable
}

pub fn internal_server_error(error: String) -> ApplicationError {
    log::error!("{}", error);
    ApplicationError::InternalServerError
}

pub fn bad_request_body(error: String) -> ApplicationError {
    log::error!("{}", error);
    ApplicationError::BadRequest(error)
}
