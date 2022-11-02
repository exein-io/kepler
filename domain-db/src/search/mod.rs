use serde::Deserialize;
use std::time::Instant;
use version_compare::Cmp;

use crate::db::models::CVE;
use crate::db::{models, Database};
use crate::sources::{nist, npm, Source};

pub trait CveCache {
    fn get(&self, query: &Query) -> Option<Vec<CVE>>;
    fn put(&self, query: Query, cves: Vec<CVE>) -> Option<Vec<CVE>>;
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct Query {
    pub vendor: Option<String>,
    pub product: String,
    pub version: Option<String>,
}

pub fn query(
    db: &Database,
    query: &Query,
    cache: Option<&dyn CveCache>,
) -> Result<Vec<models::CVE>, String> {
    log::info!("searching query: {:?} ...", query);

    // validate version string
    if let Some(ver) = &query.version {
        if version_compare::compare_to(ver, "1.0.0", Cmp::Ne).is_err() {
            return Err("invalid version string".to_owned());
        }
    }

    // Check the optional cache first
    if let Some(cache) = cache {
        if let Some(cached) = cache.get(query) {
            log::debug!("cache hit");
            return Ok(cached);
        } else {
            log::debug!("cache miss");
        }
    }

    // fetch potential candidates for this query
    let start = Instant::now();
    let candidates = db.search(query.vendor.as_ref(), &query.product)?;

    log::info!(
        "found {} candidates in {:?}",
        candidates.len(),
        start.elapsed()
    );

    // deserialize all objects belonging to the potential CVEs
    let start = Instant::now();
    let mut matches = vec![];
    let mut sources = vec![];

    for (cve, obj) in &candidates {
        match cve.source.as_str() {
            nist::SOURCE_NAME => {
                if let Ok(cve) = serde_json::from_str(&obj.data) {
                    sources.push(Source::Nist(cve));
                } else {
                    return Err(format!("could not deserialize {}", obj.cve));
                }
            }
            npm::SOURCE_NAME => {
                if let Ok(adv) = serde_json::from_str(&obj.data) {
                    sources.push(Source::Npm(adv));
                } else {
                    return Err(format!("could not deserialize {}:\n{}", obj.cve, obj.data));
                }
            }
            _ => return Err(format!("unsupported data source {}", cve.source)),
        }
    }

    log::info!(
        "deserialized the {} candidates in {:?}",
        sources.len(),
        start.elapsed()
    );

    let start = Instant::now();
    for (index, object) in sources.iter_mut().enumerate() {
        if object.is_match(query) {
            matches.push(candidates[index].0.clone());
        }
    }

    log::info!("found {} matches in {:?}", matches.len(), start.elapsed());

    // Update the optional cache
    if let Some(cache) = cache {
        log::debug!("update cache");
        cache.put(query.clone(), matches.clone());
    }

    Ok(matches)
}
