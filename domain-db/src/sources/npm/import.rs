use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Result};
use log::info;
use regex::Regex;

use super::{Advisories, SOURCE_NAME};

use crate::db::{self, Pool};
use crate::sources::download_to_file;

fn process_file(pool: &Pool, file_path: &Path) -> Result<(u32, bool)> {
    info!("processing {} ...", file_path.display());

    let mut num_imported = 0;
    let json = fs::read_to_string(&file_path)?;

    let advisories: Advisories = serde_json::from_str(&json)?;

    let database = db::Database(pool.get()?);

    let tagged_refs_parser = Regex::new(r"\[(?P<tag>[^\]]+)\]\((?P<url>[^\)]+)\)")?;
    let url_refs_parser = Regex::new(r"-\s+(?P<url>[^\s]+)")?;

    for adv in advisories.objects {
        // since we don't have a CVE, we need to build a unique identifier of some sort
        let pseudo_cve = format!("{} ({})", &adv.title, &adv.vulnerable_versions);
        // prepend 'node-' to the product name in order to avoid collisions with NVD
        // products (for instance, the tar nodejs library is called just "tar", which
        // collides with the tar unix package).
        let product = if adv.module_name.starts_with("node-") {
            adv.module_name.clone()
        } else {
            format!("node-{}", &adv.module_name)
        };

        if adv.cves.is_empty() {
            // no assigned CVEs yet, import
            let object_json = serde_json::to_string(&adv)?;
            let object_id = match database.create_object_if_not_exist(db::models::NewObject::with(
                pseudo_cve.clone(),
                object_json.clone(),
            )) {
                Err(e) => bail!(e),
                Ok(id) => id,
            };

            // parse references
            let mut refs = Vec::new();
            if !adv.references.is_empty() {
                for caps in tagged_refs_parser.captures_iter(&adv.references) {
                    refs.push(db::models::Reference {
                        url: caps["url"].into(),
                        tags: vec![caps["tag"].into()],
                    })
                }

                // fallback on just URLs
                if refs.is_empty() {
                    for caps in url_refs_parser.captures_iter(&adv.references) {
                        refs.push(db::models::Reference {
                            url: caps["url"].into(),
                            tags: vec!["url".into()],
                        })
                    }
                }
            }

            // try to create the record as new
            let new_cve = db::models::NewCVE::with(
                SOURCE_NAME.into(),
                "@npm".into(), // no vendors for npm
                product,
                pseudo_cve,
                adv.overview,
                adv.metadata.exploitability,
                adv.severity.to_ascii_uppercase(),
                None,
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
        } else {
            // if there are assigned CVEs for this advisory, try to clean the database from
            // it in case we previously imported when it didn't have any, since now we're
            // supposed to have the actual CVE from NVD.
            match database.delete_cve("@npm", &product, &pseudo_cve) {
                Err(e) => bail!(e),
                Ok(0) => {}
                Ok(_) => {
                    info!(
                        "removed NPM advisory for {} due to assigned CVE: {:?}",
                        &product, &adv.cves
                    );
                }
            }
        }
    }

    Ok((num_imported, advisories.urls.next.is_some()))
}

pub fn run(pool: &Pool, recent_only: bool, data_path: &Path) -> Result<u32> {
    let mut num_imported = 0;

    if recent_only {
        let mut file_path = data_path.to_path_buf();
        file_path.push("npm_security_advisories_1.json");
        // only download this one page, overwriting any existing version of it if present
        download_to_file(
            "https://registry.npmjs.org/-/npm/v1/security/advisories?perPage=100&page=1",
            &file_path,
        )
        .map_err(|err| anyhow!(err))?;

        let res = process_file(pool, &file_path)?;
        num_imported = res.0;
    } else {
        // download and import all available records
        let mut page = 1;
        loop {
            let mut file_path = data_path.to_path_buf();
            file_path.push(format!("npm_security_advisories_{}.json", page));
            if !file_path.exists() {
                let url = format!(
                    "https://registry.npmjs.org/-/npm/v1/security/advisories?perPage=100&page={}",
                    page
                );
                download_to_file(&url, &file_path).map_err(|err| anyhow!(err))?;
            }
            let res = process_file(pool, &file_path)?;
            num_imported += res.0;

            if res.1 {
                page += 1;
            } else {
                break;
            }
        }
    }

    Ok(num_imported)
}
