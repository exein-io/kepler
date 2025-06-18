use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use domain_db::{cve_sources::nist, db, db::KEPLER_BATCH_SIZE};
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
) -> Result<usize> {
    log::info!("connected to database, importing records ...");
    log::info!("configured 'KEPLER__BATCH_SIZE' {}", &*KEPLER_BATCH_SIZE);
    log::info!("{} CVEs pending import", cve_list.len());

    let mut num_imported = 0;

    let objects_to_insert = db::create_unique_objects(&cve_list)?
        .into_values()
        .collect::<Vec<db::models::NewObject>>();

    let inserted_object_ids = repository.insert_objects(objects_to_insert)?;
    let mut new_cves_batch: Vec<db::models::NewCVE> = Vec::with_capacity(*KEPLER_BATCH_SIZE);

    for item in &cve_list {
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
            let (score, severity, vector) = item.extract_cve_score_severity_vector();

            let object_id = inserted_object_ids
                .get(item.id())
                .cloned()
                .context(format!("Object ID not found for CVE {}", item.id()))?;

            let new_cve = db::models::NewCVE::with(
                nist::SOURCE_NAME.into(),
                product.vendor,
                product.product,
                item.id().into(),
                item.summary().map(str::to_string).unwrap_or_default(),
                score,
                severity,
                vector,
                refs.clone(),
                Some(object_id),
            );

            new_cves_batch.push(new_cve);

            // Batch insert
            if new_cves_batch.len() >= *KEPLER_BATCH_SIZE {
                let inserted = repository.batch_insert_cves(new_cves_batch)?;
                num_imported += inserted;
                if num_imported > 0 {
                    log::info!("bach imported {} cves ...", num_imported);
                }

                // Reset the collection for the next batch
                new_cves_batch = Vec::with_capacity(*KEPLER_BATCH_SIZE);
            }
        }
    }

    // Batch insert Remaining CVEs
    if !new_cves_batch.is_empty() {
        let inserted = repository.batch_insert_cves(new_cves_batch)?;
        num_imported += inserted;
    }

    log::info!("imported {} records Total", num_imported);
    Ok(num_imported)
}

fn report_message(num_records: usize) -> Cow<'static, str> {
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
