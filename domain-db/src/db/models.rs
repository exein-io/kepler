use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::schema::{cves, objects};

#[derive(Debug, Serialize)]
pub struct Product {
    pub vendor: String,
    pub product: String,
}

#[derive(Queryable, Debug)]
pub struct Object {
    pub id: i32,
    pub created_at: SystemTime,
    pub updated_at: Option<SystemTime>,
    pub cve: String,
    pub data: String,
}

#[derive(Debug, Insertable)]
#[table_name = "objects"]
pub struct NewObject {
    pub created_at: SystemTime,
    pub cve: String,
    pub data: String,
}

impl NewObject {
    pub fn with(cve: String, data: String) -> Self {
        Self {
            created_at: SystemTime::now(),
            cve,
            data,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Reference {
    pub url: String,
    pub tags: Vec<String>,
}

pub type References = Vec<Reference>;

#[derive(Queryable, Debug, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct CVE {
    #[serde(skip_serializing)]
    pub id: i32,
    #[serde(skip_serializing)]
    pub created_at: SystemTime,
    #[serde(skip_serializing)]
    pub updated_at: Option<SystemTime>,
    pub source: String,
    pub vendor: String,
    pub product: String,
    pub cve: String,
    pub summary: String,
    pub score: f64,
    pub severity: String,
    pub vector: Option<String>,
    pub references: diesel_json::Json<References>,
    #[serde(skip_serializing)]
    pub object_id: Option<i32>,
}

#[derive(Debug, Insertable)]
#[table_name = "cves"]
pub struct NewCVE {
    pub created_at: SystemTime,
    pub source: String,
    pub vendor: String,
    pub product: String,
    pub cve: String,
    pub summary: String,
    pub score: f64,
    pub severity: String,
    pub vector: Option<String>,
    pub references: diesel_json::Json<References>,
    pub object_id: Option<i32>,
}

impl NewCVE {
    // not worth implementing a builder pattern just for this
    #![allow(clippy::too_many_arguments)]
    pub fn with(
        source: String,
        vendor: String,
        product: String,
        cve: String,
        summary: String,
        score: f64,
        severity: String,
        vector: Option<String>,
        references: References,
        object_id: Option<i32>,
    ) -> Self {
        let references = diesel_json::Json::new(references);
        Self {
            created_at: SystemTime::now(),
            source,
            vendor,
            product,
            cve,
            summary,
            score,
            severity,
            vector,
            references,
            object_id,
        }
    }
}
