use std::sync::Mutex;
use std::time::Instant;

use lazy_static::lazy_static;
use log::info;
use lru::LruCache;
use serde::Deserialize;
use version_compare::{CompOp, VersionCompare};

use crate::db::{models, Database};
use crate::sources::{nist, npm, Source};

lazy_static! {
    static ref CACHE: Mutex<LruCache<Query, Vec<models::CVE>>> = Mutex::new(LruCache::new(4096));
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct Query {
    pub vendor: Option<String>,
    pub product: String,
    pub version: Option<String>,
}

pub fn query(db: &Database, query: &Query) -> Result<Vec<models::CVE>, String> {
    info!("searching query: {:?} ...", query);

    // validate version string
    if let Some(ver) = &query.version {
        if VersionCompare::compare_to(ver, "1.0.0", &CompOp::Ne).is_err() {
            return Err("invalid version string".to_owned());
        }
    }

    let mut cache = CACHE.lock().unwrap();
    Ok(if let Some(cached) = cache.get(query) {
        info!("cache hit");
        cached.to_vec()
    } else {
        info!("cache miss");

        // fetch potential candidates for this query
        let start = Instant::now();
        let candidates = db.search(query.vendor.as_ref(), &query.product)?;

        info!(
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

        info!(
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

        info!("found {} matches in {:?}", matches.len(), start.elapsed());

        cache.put(query.clone(), matches.clone());
        matches
    })
}
