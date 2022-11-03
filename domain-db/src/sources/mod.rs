use std::{fs::File, path::Path};

use serde::Deserialize;
use version_compare::Cmp;

use crate::db::Query;

pub mod nist;

#[derive(Debug, Deserialize)]
pub enum Source {
    Nist(nist::cve::item::CVE),
}

impl Source {
    pub fn is_match(&mut self, query: &Query) -> bool {
        match self {
            Self::Nist(cve) => cve.is_match(query),
        }
    }
}

pub(crate) fn version_cmp(a: &str, b: &str, operator: Cmp) -> bool {
    if let Ok(res) = version_compare::compare_to(a, b, operator) {
        return res;
    } else {
        log::warn!(
            "could not compare versions {} and {} with {:?}",
            a,
            b,
            operator
        );
    }
    false
}

pub(crate) fn download_to_file(url: &str, file_name: &Path) -> Result<(), String> {
    log::info!("downloading {} to {} ...", url, file_name.display(),);

    let client = reqwest::blocking::Client::builder()
        .timeout(Some(std::time::Duration::from_secs(300)))
        .build()
        .map_err(|e| format!("could not create http client: {}", e))?;
    let mut res = client
        .get(url)
        .send()
        .map_err(|e| format!("error downloading file: {}", e))?;

    let mut file = File::create(file_name)
        .map_err(|e| format!("could not create {}: {}", file_name.display(), e))?;

    res.copy_to(&mut file)
        .map_err(|e| format!("could not download {}: {}", file_name.display(), e))?;

    Ok(())
}
