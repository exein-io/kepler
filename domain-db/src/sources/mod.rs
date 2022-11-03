use std::{fs::File, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;
use version_compare::Cmp;

pub mod nist;

#[derive(Debug, Deserialize)]
pub enum Source {
    Nist(nist::cve::item::CVE),
}

impl Source {
    pub fn is_match(&mut self, product: &str, version: &str) -> bool {
        match self {
            Self::Nist(cve) => cve.is_match(product, version),
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

pub(crate) fn download_to_file(url: &str, file_name: &Path) -> Result<()> {
    log::info!("downloading {} to {} ...", url, file_name.display(),);

    let client = reqwest::blocking::Client::builder()
        .timeout(Some(std::time::Duration::from_secs(300)))
        .build()
        .context("could not create http client")?;
    let mut res = client
        .get(url)
        .send()
        .with_context(|| format!("error downloading: {url}"))?;

    let mut file = File::create(file_name)
        .with_context(|| format!("could not create {}", file_name.display()))?;

    res.copy_to(&mut file)
        .with_context(|| format!("could not download to {}", file_name.display()))?;

    Ok(())
}
