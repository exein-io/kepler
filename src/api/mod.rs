use std::env;

use dotenv::dotenv;
use rocket::routes;

use crate::db;

pub mod cves;
pub mod products;

#[get("/")]
pub fn index() -> &'static str {
    "pong"
}

pub fn run() {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap();

    rocket::ignite()
        .manage(db::setup(&database_url).unwrap())
        .mount("/cve", routes![cves::search])
        .mount(
            "/products",
            routes![products::all, products::by_vendor, products::search],
        )
        .mount("/", routes![index])
        .launch();
}
