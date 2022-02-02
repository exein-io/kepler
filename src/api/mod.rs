use std::env;

use actix_cors::Cors;
use actix_web::{
    dev::Server,
    web::{self, Data},
    App, HttpServer,
};
use dotenv::dotenv;

use crate::db::{self, Database, Pool};

mod cves;
mod error;
mod products;
mod utils;

pub fn run() -> Result<Server, anyhow::Error> {
    dotenv().ok();

    let host = "0.0.0.0";
    let port = 8000;

    let database_url = env::var("DATABASE_URL").unwrap();

    let pool = db::setup(&database_url).map_err(anyhow::Error::msg)?;

    let application_ctx = Data::new(ApplicationContext { pool });

    let server = HttpServer::new(move || {
        App::new()
            .app_data(application_ctx.clone())
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
