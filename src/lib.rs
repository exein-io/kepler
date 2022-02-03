#[macro_use]
extern crate diesel;
extern crate r2d2;
extern crate r2d2_diesel;

use lazy_static::lazy_static;

pub mod api;
pub mod db;
pub mod search;
pub mod sources;
pub mod utils;

pub fn version() -> &'static str {
    #[cfg(debug_assertions)]
    lazy_static! {
        static ref VERSION: String = format!("{}+dev", env!("CARGO_PKG_VERSION"));
    }

    #[cfg(not(debug_assertions))]
    lazy_static! {
        static ref VERSION: String = env!("CARGO_PKG_VERSION").to_string();
    }
    &VERSION
}
