use anyhow::{Context, Result};
use clap::{App, AppSettings, Arg};
use dotenv::dotenv;
use env_logger::Env;
use std::{env, fs, path::PathBuf};

use kepler::{
    api, db,
    sources::{nist, npm},
};

#[actix_web::main]
async fn main() -> Result<()> {
    let matches = App::new("nvdio")
        .version(kepler::version())
        .about("Kepler vulnerability database search engine")
        .setting(AppSettings::DisableHelpSubcommand)
        .arg(
            Arg::new("migrate")
                .short('m')
                .long("migrate")
                .takes_value(false)
                .help("Migrate database"),
        )
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
                        .takes_value(false)
                        .help("Download fresh files"),
                ),
        )
        .subcommand(
            App::new("import_npm")
                .about("imports vulnerabilities from the registry.npmjs.org data feed")
                .arg(
                    Arg::new("recent")
                        .short('r')
                        .long("recent")
                        .takes_value(false)
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

    dotenv().ok();

    // Database pool connection
    let pool = {
        let database_url = env::var("DATABASE_URL")
            .context("DATABASE_URL environment variable has not specified.")?;
        db::setup(&database_url).context("Cannot connect to database")?
    };

    // Setup logger
    {
        #[cfg(debug_assertions)]
        let default_env_filter = "debug";
        #[cfg(not(debug_assertions))]
        let default_env_filter = "info";

        match matches.subcommand() {
            Some(_) => {
                // Init logger for non web application
                let env = Env::default().default_filter_or(default_env_filter);
                env_logger::Builder::from_env(env).try_init()
            }
            None => {
                // Init tracer for web application
                api::init_logger(default_env_filter)
            }
        }
        .context("Failed to setup logger")?;
    }

    // Setup database if needed and check for migrations
    {
        let conn = pool.get()?;

        diesel_migrations::setup_database(&*conn)?;

        if diesel_migrations::any_pending_migrations(&*conn)? {
            if matches.is_present("migrate") {
                diesel_migrations::run_pending_migrations(&*conn)?;
                log::info!("Migration successfully")
            } else {
                log::error!("Migration needed");
                std::process::exit(1)
            }
        }
    }

    match matches.subcommand() {
        Some((exec_name, matches)) => {
            // Handle data directory creation
            let data_path = PathBuf::from(matches.value_of("data").unwrap());
            if !data_path.exists() {
                log::info!("creating {}", data_path.display());
                fs::create_dir_all(&data_path).expect("could not create data path");
            }

            // Import by command
            let num_records = match exec_name {
                "import_nist" => nist::import::run(
                    &pool,
                    matches.value_of("year").unwrap(),
                    &data_path,
                    matches.is_present("fresh"),
                ),

                "import_npm" => npm::import::run(&pool, matches.is_present("recent"), &data_path),

                _ => unreachable!("Trying to launch a not existent subcommand"),
            }?;

            let report = report_message(num_records);

            log::info!("{report}");
        }
        None => api::run(pool)?.await?,
    }

    Ok(())
}

fn report_message(num_records: u32) -> String {
    if num_records == 0 {
        "No new records created".to_string()
    } else {
        format!("{num_records} new records created")
    }
}
