use actix_web::error::BlockingError;

use super::error::ApplicationError;

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
