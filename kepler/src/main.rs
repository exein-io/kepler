use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use domain_db::{cve_sources::nist, db};
use dotenvy::dotenv;
use env_logger::Env;
use lazy_static::lazy_static;
use std::borrow::Cow;
use std::{fs, path::Path};

mod api;
mod configuration;

use crate::api::ApiConfig;
use crate::configuration::{ApiSettings, DatabaseSettings};

#[actix_web::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    dotenv().ok();

    // Repository
    let repository = {
        let db_settings = DatabaseSettings::try_from_env()?;

        db::PostgresRepository::new(&db_settings.connection_string(), "./migrations")
            .context("Cannot connect to database")?
    };

    // Setup logger
    {
        #[cfg(debug_assertions)]
        let default_env_filter = "debug";
        #[cfg(not(debug_assertions))]
        let default_env_filter = "info";

        if opts.cmd.is_none() {
            // Init tracer for web application
            api::init_logger(default_env_filter)
        } else {
            // Init logger for non web application
            let env = Env::default().default_filter_or(default_env_filter);
            env_logger::Builder::from_env(env).try_init()
        }
        .context("Failed to setup logger")?;
    }

    // Setup database if needed and check for migrations
    {
        repository.setup_database()?;

        if repository.any_pending_migrations()? {
            if opts.migrate {
                repository.run_pending_migrations()?;
                log::info!("Migration successfully")
            } else {
                log::error!("Migration needed");
                std::process::exit(1)
            }
        }
    }

    match opts.cmd {
        Some(Commands::ImportNist {
            year,
            data_dir,
            refresh,
        }) => {
            let data_path = check_data_path(&data_dir);

            let (_, cve_list) = nist::download(year, data_path, refresh)?;

            let num_records = import_nist(&repository, cve_list)?;

            let report = report_message(num_records);

            log::info!("{report}");
        }
        None => {
            let ApiSettings { address, port } = ApiSettings::try_from_env()?;

            log::info!("Start listening on {}:{}...", address, port);

            let api_config = ApiConfig {
                address,
                port,
                repository,
            };

            api::run(api_config)?.await?
        }
    }

    Ok(())
}

#[derive(Parser)]
#[command(author, version, about)]
#[command(disable_help_subcommand = true)]
struct Opts {
    /// Migrate database
    #[arg(short = 'm', long = "migrate")]
    migrate: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Imports the specified year of CVE from the NIST data feed
    #[command(name = "import_nist")]
    ImportNist {
        /// Data path
        #[arg(short = 'd', long = "data", default_value_t = String::from("./data"))]
        data_dir: String,

        /// Force download files again
        #[arg(short = 'f', long = "refresh")]
        refresh: bool,

        /// The year to import
        year: u16,
    },
}

/// Handle data directory creation if not existing
fn check_data_path(data_path: &str) -> &Path {
    let data_path = Path::new(data_path);
    if !data_path.exists() {
        log::info!("creating {}", data_path.display());
        fs::create_dir_all(data_path).expect("could not create data path");
    }
    data_path
}

pub fn import_nist(
    repository: &db::PostgresRepository,
    cve_list: Vec<nist::cve::CVE>,
) -> Result<u32> {
    log::info!("connected to database, importing records ...");

    let mut num_imported = 0;

    for item in &cve_list {
        let json = serde_json::to_string(item)?;

        let object_id = repository
            .create_object_if_not_exist(db::models::NewObject::with(item.id().into(), json))?;

        let refs = item
            .cve
            .references
            .reference_data
            .iter()
            .map(|data| db::models::Reference {
                url: data.url.clone(),
                tags: data.tags.clone(),
            })
            .collect::<Vec<_>>();

        for product in item.collect_unique_products() {
            let new_cve = db::models::NewCVE::with(
                nist::SOURCE_NAME.into(),
                product.vendor,
                product.product,
                item.id().into(),
                item.summary().map(str::to_string).unwrap_or_default(),
                Default::default(),
                Default::default(),
                Default::default(),
                refs.clone(),
                Some(object_id),
            );

            if repository.create_cve_if_not_exist(new_cve)? {
                num_imported += 1;
                if num_imported % 100 == 0 {
                    log::info!("imported {} records ...", num_imported);
                }
            };
        }
    }

    Ok(num_imported)
}

fn report_message(num_records: u32) -> Cow<'static, str> {
    if num_records == 0 {
        Cow::Borrowed("No new records created")
    } else {
        Cow::Owned(format!("{num_records} new records created"))
    }
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
