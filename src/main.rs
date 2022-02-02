#[macro_use]
extern crate diesel;
extern crate r2d2;
extern crate r2d2_diesel;

use clap::{App, AppSettings, Arg};
use env_logger::Env;
use lazy_static::lazy_static;
use log::info;
use std::fs;
use std::path::PathBuf;

mod api;
mod db;
mod search;
mod sources;
mod utils;

fn import_nist(matches: &clap::ArgMatches) {
    let data_path = PathBuf::from(matches.value_of("data").unwrap());
    if !data_path.exists() {
        info!("creating {}", data_path.display());
        fs::create_dir_all(&data_path).expect("could not create data path");
    }
    match sources::nist::import::run(
        matches.value_of("year").unwrap(),
        &data_path,
        matches.is_present("fresh"),
    ) {
        Err(e) => panic!("{}", e),
        Ok(0) => info!("no new records created"),
        Ok(n) => info!("{} new records created", n),
    }
}

fn import_npm(matches: &clap::ArgMatches) {
    let data_path = PathBuf::from(matches.value_of("data").unwrap());
    if !data_path.exists() {
        info!("creating {}", data_path.display());
        fs::create_dir_all(&data_path).expect("could not create data path");
    }
    match sources::npm::import::run(matches.is_present("recent"), &data_path) {
        Err(e) => panic!("{}", e),
        Ok(0) => info!("no new records created"),
        Ok(n) => info!("{} new records created", n),
    }
}

#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
    let matches = App::new("nvdio")
        .version(crate::version())
        .about("Kepler vulnerability database search engine")
        .setting(AppSettings::DisableHelpSubcommand)
        .subcommand(
            App::new("import_nist")
                .about("imports the specified year of CVE from the NIST data feed")
                .arg(
                    Arg::new("year")
                        .help("the year to import")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .default_value("./data")
                        .help("Data path."),
                )
                .arg(
                    Arg::new("fresh")
                        .short('f')
                        .long("fresh")
                        .help("Download fresh files."),
                ),
        )
        .subcommand(
            App::new("import_npm")
                .about("imports vulnerabilities from the registry.npmjs.org data feed")
                .arg(
                    Arg::new("recent")
                        .short('r')
                        .long("recent")
                        .help("only download recent records"),
                )
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .default_value("./data")
                        .help("Data path."),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some((exec_name, matches)) => {
            // Init logger for non web application
            env_logger::Builder::from_env(Env::default()).init();

            match exec_name {
                "import_nist" => import_nist(matches),
                "import_npm" => import_npm(matches),
                _ => unreachable!("Trying to launch a not existent subcommand"),
            }
        }
        None => api::run()?.await?,
    }

    Ok(())
}

fn version() -> &'static str {
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
