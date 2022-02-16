use std::path::Path;

use anyhow::{anyhow, bail, Result};
use log::info;

use super::{cve, SOURCE_NAME};
use crate::db::{self, Pool};

pub fn run(pool: &Pool, year: &str, data_path: &Path, fresh: bool) -> Result<u32> {
    let (_, mut cve_list) = cve::setup(year, data_path, fresh).map_err(|err| anyhow!(err))?;

    let database = db::Database(pool.get()?);

    info!("connected to database, importing records ...");

    let mut num_imported = 0;

    for item in &mut cve_list.items {
        let json = serde_json::to_string(item)?;

        let object_id = match database
            .create_object_if_not_exist(db::models::NewObject::with(item.id().into(), json))
        {
            Err(e) => bail!(e),
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
                Err(e) => bail!(e),
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
