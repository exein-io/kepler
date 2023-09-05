use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use configuration::DatabaseSettings;
use domain_db::{cve_sources::nist, db};
use dotenvy::dotenv;
use env_logger::Env;
use std::{fs, path::Path};

mod configuration;

use kepler::api::{self, ApiConfig};

use crate::configuration::ApiSettings;

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
        Some(cmd) => match cmd {
            Commands::ImportNist {
                year,
                data_dir,
                refresh,
            } => {
                let data_path = check_data_path(&data_dir);

                let (_, cve_list) = nist::download(year, data_path, refresh)?;

                let num_records = import_nist(&repository, cve_list)?;

                let report = report_message(num_records);

                log::info!("{report}");
            }
        },
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

        let object_id = match repository
            .create_object_if_not_exist(db::models::NewObject::with(item.id().into(), json))
        {
            Err(e) => bail!(e),
            Ok(id) => id,
        };

        let mut refs = Vec::new();
        for data in &item.cve.references.reference_data {
            refs.push(db::models::Reference {
                url: data.url.clone(),
                tags: data.tags.clone(),
            })
        }

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
            match repository.create_cve_if_not_exist(new_cve) {
                Err(e) => bail!(e),
                Ok(true) => num_imported += 1,
                Ok(false) => {}
            }

            if num_imported > 0 && num_imported % 100 == 0 {
                log::info!("imported {} records ...", num_imported);
            }
        }
    }

    Ok(num_imported)
}

fn report_message(num_records: u32) -> String {
    if num_records == 0 {
        "No new records created".to_string()
    } else {
        format!("{num_records} new records created")
    }
}
