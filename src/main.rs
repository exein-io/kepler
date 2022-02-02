#[macro_use]
extern crate diesel;
extern crate r2d2;
extern crate r2d2_diesel;

use clap::{App, Arg, SubCommand};
use std::fs;
use std::path::PathBuf;

use env_logger::Env;
use log::info;

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
        .subcommand(
            SubCommand::with_name("import_nist")
                .about("imports the specified year of CVE from the NIST data feed")
                .arg(
                    Arg::with_name("year")
                        .help("the year to import")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name("data")
                        .short("d")
                        .long("data")
                        .default_value("./data")
                        .help("Data path."),
                )
                .arg(
                    Arg::with_name("fresh")
                        .short("f")
                        .long("fresh")
                        .help("Download fresh files."),
                ),
        )
        .subcommand(
            SubCommand::with_name("import_npm")
                .about("imports vulnerabilities from the registry.npmjs.org data feed")
                .arg(
                    Arg::with_name("recent")
                        .short("r")
                        .long("recent")
                        .help("only download recent records"),
                )
                .arg(
                    Arg::with_name("data")
                        .short("d")
                        .long("data")
                        .default_value("./data")
                        .help("Data path."),
                ),
        )
        .get_matches();

    env_logger::Builder::from_env(Env::default()).init();

    if let Some(matches) = matches.subcommand_matches("import_nist") {
        import_nist(matches);
    } else if let Some(matches) = matches.subcommand_matches("import_npm") {
        import_npm(matches);
    } else {
        api::run()?.await?;
    }
    Ok(())
}
