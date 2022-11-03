use anyhow::{Context, Result};
use clap::{Arg, Command};
use domain_db::{db, sources::nist};
use env_logger::Env;
use std::{env, fs, path::PathBuf};

use kepler::api::{self, ApiConfig};

#[actix_web::main]
async fn main() -> Result<()> {
    let matches = Command::new("kepler")
        .version(kepler::version())
        .about("Kepler vulnerability database search engine")
        .disable_help_subcommand(true)
        .arg(
            Arg::new("migrate")
                .short('m')
                .long("migrate")
                .takes_value(false)
                .help("Migrate database"),
        )
        .subcommand(
            Command::new("import_nist")
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
            Command::new("import_npm")
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

    // Repository
    let repository = {
        let database_url = env::var("DATABASE_URL")
            .context("DATABASE_URL environment variable has not specified.")?;
        db::PostgresRepository::new(&database_url).context("Cannot connect to database")?
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
        repository.setup_database()?;

        if repository.any_pending_migrations()? {
            if matches.is_present("migrate") {
                repository.run_pending_migrations()?;
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
                    &repository,
                    matches.value_of("year").unwrap(),
                    &data_path,
                    matches.is_present("fresh"),
                ),

                _ => unreachable!("Trying to launch a not existent subcommand"),
            }?;

            let report = report_message(num_records);

            log::info!("{report}");
        }
        None => {
            let host = env::var("KEPLER_ADDRESS")
                .map_err(|_| "Invalid or missing custom address")
                .unwrap_or_else(|err| {
                    log::warn!("{}. Using default 0.0.0.0", err);
                    "0.0.0.0".to_string()
                });
            let port = env::var("KEPLER_PORT")
                .map_err(|_| "Invalid or missing custom port")
                .and_then(|s| s.parse::<u16>().map_err(|_| "Failed to parse custom port"))
                .unwrap_or_else(|err| {
                    log::warn!("{}. Using default 8000", err);
                    8000
                });

            let api_config = ApiConfig {
                host,
                port,
                repository,
            };

            api::run(api_config)?.await?
        }
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
