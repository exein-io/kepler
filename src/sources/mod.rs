use serde::Deserialize;

use crate::search::Query;

pub mod nist;
pub mod npm;

#[derive(Debug, Deserialize)]
pub enum Source {
    Nist(nist::cve::item::CVE),
    Npm(npm::Advisory),
}

impl Source {
    pub fn is_match(&mut self, query: &Query) -> bool {
        match self {
            Self::Nist(cve) => cve.is_match(query),
            Self::Npm(advisory) => advisory.is_match(query),
        }
    }
}
