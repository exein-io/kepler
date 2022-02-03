use std::env;

use actix_cors::Cors;
use actix_web::{
    dev::Server,
    web::{self, Data},
    App, HttpResponse, HttpServer,
};
use dotenv::dotenv;
use serde::Serialize;

use crate::db::{self, Database, Pool};

mod cves;
mod error;
mod products;
mod utils;

pub fn run() -> Result<Server, anyhow::Error> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("Can't find DATABASE_URL env variable");
    let host = env::var("KEPLER_ADDRESS")
        .map_err(|_| "Invalid or missing custom address")
        .unwrap_or_else(|err| {
            println!("{}. Using default 0.0.0.0", err);
            "0.0.0.0".to_string()
        });
    let port = env::var("KEPLER_PORT")
        .map_err(|_| "Invalid or missing custom port")
        .and_then(|s| s.parse::<u16>().map_err(|_| "Failed to parse custom port"))
        .unwrap_or_else(|err| {
            println!("{}. Using default 8000", err);
            8000
        });

    let pool = db::setup(&database_url).map_err(anyhow::Error::msg)?;

    let application_ctx = Data::new(ApplicationContext { pool });

    let server = HttpServer::new(move || {
        App::new()
            .app_data(application_ctx.clone())
            .route("/health_check", web::get().to(health_check))
            .service(
                web::scope("/cve") //
                    .route("/search", web::post().to(cves::search)), // List of connected agent
            )
            .service(
                web::scope("/products") //
                    .route("/", web::get().to(products::all)) // List of connected agent
                    .route("/by_vendor", web::get().to(products::by_vendor)) // Agent detail
                    .route("/search/{query}", web::get().to(products::search)), // Monitor agent
            )
            .wrap(Cors::permissive())
            .wrap(tracing_actix_web::TracingLogger::default())
    })
    .bind((host, port))?
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

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(HealthCheck {
        version: crate::version(),
    })
}
