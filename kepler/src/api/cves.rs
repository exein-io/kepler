use std::{num::NonZeroUsize, sync::Mutex};

use actix_web::web::{self, Json};
use lazy_static::lazy_static;
use lru::LruCache;

use domain_db::db::{MatchedCVE, Query};

use super::{
    error::{bad_request_body, handle_blocking_error, ApplicationError},
    ApplicationContext,
};

lazy_static! {
    static ref CACHE: CveLruCache = CveLruCache::new(NonZeroUsize::new(4096).unwrap());
}

struct CveLruCache(Mutex<LruCache<Query, Vec<MatchedCVE>>>);

impl CveLruCache {
    fn new(cap: NonZeroUsize) -> Self {
        Self(Mutex::new(LruCache::new(cap)))
    }

    fn get(&self, query: &Query) -> Option<Vec<MatchedCVE>> {
        let mut inner = self.0.lock().unwrap();
        inner.get(query).cloned()
    }

    fn put(&self, query: Query, cves: Vec<MatchedCVE>) -> Option<Vec<MatchedCVE>> {
        self.0.lock().unwrap().put(query, cves)
    }
}

pub async fn search(
    ctx: web::Data<ApplicationContext>,
    query: Json<Query>,
) -> Result<Json<Vec<MatchedCVE>>, ApplicationError> {
    // Check the cache first
    if let Some(cached) = CACHE.get(&query) {
        log::debug!("cache hit");
        return Ok(Json(cached));
    } else {
        log::debug!("cache miss");
    }

    // Query the db
    let cves = {
        let query = query.clone();

        web::block(move || {
            let repository = ctx.get_repository();
            repository.query(&query).map_err(bad_request_body)
        })
        .await
        .map_err(handle_blocking_error)??
    };

    // Update the optional cache
    log::debug!("update cache");
    CACHE.put(query.0, cves.clone());

    Ok(Json(cves))
}
