use std::sync::Mutex;

use actix_web::web::{self, Json};
use lazy_static::{__Deref, lazy_static};
use lru::LruCache;

use domain_db::{
    db::models::{self, CVE},
    search::{self, CveCache, Query},
};

use super::{
    error::{bad_request_body, handle_blocking_error, handle_database_error, ApplicationError},
    ApplicationContext,
};

lazy_static! {
    static ref CACHE: CveLruCache = CveLruCache::new(4096);
}

struct CveLruCache(Mutex<LruCache<Query, Vec<models::CVE>>>);

impl CveLruCache {
    fn new(cap: usize) -> Self {
        Self(Mutex::new(LruCache::new(cap)))
    }
}

impl CveCache for CveLruCache {
    fn get(&self, query: &Query) -> Option<Vec<CVE>> {
        let mut inner = self.0.lock().unwrap();
        inner.get(query).map(Vec::clone)
    }

    fn put(&self, query: Query, cves: Vec<CVE>) -> Option<Vec<CVE>> {
        self.0.lock().unwrap().put(query, cves)
    }
}

pub async fn search(
    ctx: web::Data<ApplicationContext>,
    query: Json<Query>,
) -> Result<Json<Vec<CVE>>, ApplicationError> {
    let cves = web::block(move || {
        let database = ctx.get_database().map_err(handle_database_error)?;
        search::query(&database, &query.into_inner(), Some(CACHE.deref())).map_err(bad_request_body)
    })
    .await
    .map_err(handle_blocking_error)??;

    Ok(Json(cves))
}
