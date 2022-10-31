use lazy_static::lazy_static;

pub mod api;

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
