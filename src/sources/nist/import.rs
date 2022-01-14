use std::env;
use std::path::Path;

use dotenv::dotenv;
use log::info;

use super::{cve, SOURCE_NAME};
use crate::db;

pub fn run(year: &str, data_path: &Path, fresh: bool) -> Result<u32, String> {
    let (_, mut cve_list) = cve::setup(year, data_path, fresh)?;

    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL environment variable has not specified.")?;
    let pool = db::setup(&database_url)?;
    let database = db::Database(pool.get().unwrap());

    info!("connected to database, importing records ...");

    let mut num_imported = 0;

    for item in &mut cve_list.items {
        let json = serde_json::to_string(item).map_err(|e| e.to_string())?;

        let object_id = match database
            .create_object_if_not_exist(db::models::NewObject::with(item.id().into(), json))
        {
            Err(e) => return Err(e),
            Ok(id) => id,
        };

        let mut refs = db::models::References::default();
        for data in &item.cve.references.reference_data {
            refs.push(db::models::Reference {
                url: data.url.clone(),
                tags: data.tags.clone(),
            })
        }

        for product in item.collect_unique_products() {
            let new_cve = db::models::NewCVE::with(
                SOURCE_NAME.into(),
                product.vendor,
                product.product,
                item.id().into(),
                item.summary().into(),
                item.score(),
                item.severity().into(),
                Some(item.vector().into()),
                refs.clone(),
                Some(object_id),
            );
            match database.create_cve_if_not_exist(new_cve) {
                Err(e) => return Err(e),
                Ok(true) => num_imported += 1,
                Ok(false) => {}
            }

            if num_imported > 0 && num_imported % 100 == 0 {
                info!("imported {} records ...", num_imported);
            }
        }
    }

    Ok(num_imported)
}
