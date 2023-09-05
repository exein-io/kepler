use actix_cors::Cors;
use actix_web::{
    dev::Server,
    web::{self, Data, Json},
    App, HttpServer,
};

use serde::Serialize;

use domain_db::db::PostgresRepository;

mod cves;
mod error;
mod products;
mod telemetry;

pub use telemetry::init_logger;

pub struct ApiConfig {
    pub address: String,
    pub port: u16,
    pub repository: PostgresRepository,
}

pub fn run(api_config: ApiConfig) -> Result<Server, anyhow::Error> {
    let application_ctx = Data::new(ApplicationContext {
        repository: api_config.repository,
    });

    let server = HttpServer::new(move || {
        App::new()
            .app_data(application_ctx.clone())
            .route("/health_check", web::get().to(health_check))
            .service(
                web::scope("/cve") //
                    .route("/search", web::post().to(cves::search)),
            )
            .service(
                web::scope("/products") //
                    .route("/", web::get().to(products::all))
                    .route("/by_vendor", web::get().to(products::by_vendor))
                    .route("/search/{query}", web::get().to(products::search)),
            )
            .wrap(Cors::permissive())
            .wrap(tracing_actix_web::TracingLogger::default())
    })
    .bind((api_config.address, api_config.port))?
    .run();
    Ok(server)
}

pub struct ApplicationContext {
    repository: PostgresRepository,
}

impl ApplicationContext {
    pub fn get_repository(&self) -> &PostgresRepository {
        &self.repository
    }
}

#[derive(Debug, Serialize)]
struct HealthCheck<'a> {
    version: &'a str,
}

async fn health_check() -> Json<HealthCheck<'static>> {
    Json(HealthCheck {
        version: crate::version(),
    })
}
