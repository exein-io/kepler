use actix_cors::Cors;
use actix_web::{
    dev::Server,
    web::{self, Data, Json},
    App, HttpServer,
};

use serde::Serialize;

use crate::db::{Database, Pool};

mod cves;
mod error;
mod products;
mod telemetry;

pub use telemetry::init_logger;

pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub pool: Pool,
}

pub fn run(api_config: ApiConfig) -> Result<Server, anyhow::Error> {
    let application_ctx = Data::new(ApplicationContext {
        pool: api_config.pool,
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
    .bind((api_config.host, api_config.port))?
    .run();
    Ok(server)
}

pub struct ApplicationContext {
    pool: Pool,
}

impl ApplicationContext {
    pub fn get_database(&self) -> Result<Database, r2d2::Error> {
        let pool = self.pool.get()?;
        Ok(Database(pool))
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
