use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub mod node;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Meta {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ASSIGNER")]
    assigner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Reference {
    pub url: String,
    pub name: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct References {
    pub reference_data: Vec<Reference>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DescriptionData {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Description {
    pub description_data: Vec<DescriptionData>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Info {
    #[serde(rename = "CVE_data_meta")]
    pub meta: Meta,
    pub references: References,
    pub description: Description,
    #[serde(rename = "problemtype")]
    pub problem_type: ProblemType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProblemType {
    #[serde(rename = "problemtype_data")]
    problem_type_data: Vec<ProblemTypeDataItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProblemTypeDataItem {
    pub description: Vec<ProblemTypeDescription>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProblemTypeDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CVSSV2 {
    pub version: String,
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    #[serde(rename = "accessVector")]
    pub access_vector: String,
    #[serde(rename = "accessComplexity")]
    pub access_complexity: String,
    pub authentication: String,
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: String,
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: String,
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: String,
    #[serde(rename = "baseScore")]
    pub base_score: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CVSSV3 {
    pub version: String,
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    #[serde(rename = "attackVector")]
    pub attack_vector: String,
    #[serde(rename = "attackComplexity")]
    pub attack_complexity: String,
    #[serde(rename = "privilegesRequired")]
    pub privileges_required: String,
    #[serde(rename = "userInteraction")]
    pub user_interaction: String,
    pub scope: String,
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: String,
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: String,
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: String,
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImpactMetricV2 {
    #[serde(rename = "cvssV2")]
    pub cvss: CVSSV2,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: f32,
    #[serde(rename = "impactScore")]
    pub impact_score: f32,
    pub severity: String,
    #[serde(rename = "acInsufInfo")]
    pub ac_insuf_info: Option<bool>,
    #[serde(rename = "obtainAllPrivilege")]
    pub obtain_all_privilege: bool,
    #[serde(rename = "obtainUserPrivilege")]
    pub obtain_user_privilege: bool,
    #[serde(rename = "obtainOtherPrivilege")]
    pub obtain_other_privilege: bool,
    #[serde(rename = "userInteractionRequired")]
    pub user_interaction_required: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImpactMetricV3 {
    #[serde(rename = "cvssV3")]
    pub cvss: CVSSV3,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: f32,
    #[serde(rename = "impactScore")]
    pub impact_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Impact {
    // TODO: Implement V1?
    #[serde(rename = "baseMetricV2")]
    pub metric_v2: Option<ImpactMetricV2>,
    #[serde(rename = "baseMetricV3")]
    pub metric_v3: Option<ImpactMetricV3>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configurations {
    #[serde(rename = "CVE_data_version")]
    pub data_version: String,
    pub nodes: Vec<node::Node>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct CVE {
    pub cve: Info,
    pub impact: Impact,
    pub configurations: Configurations,
    #[serde(rename = "publishedDate")]
    pub published_date: String,
    #[serde(rename = "lastModifiedDate")]
    pub last_modified_date: String,
}

impl CVE {
    pub fn is_complete(&self) -> bool {
        !self.configurations.nodes.is_empty()
    }

    pub fn id(&self) -> &str {
        &self.cve.meta.id
    }

    pub fn summary(&self) -> Option<&str> {
        for desc in &self.cve.description.description_data {
            if desc.lang == "en" {
                return Some(&desc.value);
            }
        }
        None
    }

    pub fn problems(&self) -> Vec<&str> {
        self.cve
            .problem_type
            .problem_type_data
            .iter()
            .flat_map(|item| {
                item.description
                    .iter()
                    .map(|description_item| description_item.value.as_str())
            })
            .collect()
    }

    pub fn collect_unique_products(&self) -> HashSet<cpe::Product> {
        self.configurations
            .nodes
            .iter()
            .flat_map(|node| node.collect_unique_products())
            .collect()
    }

    pub fn is_match(&mut self, product: &str, version: &str) -> bool {
        for root in &mut self.configurations.nodes {
            // roots are implicitly in OR
            if root.is_match(product, version) {
                return true;
            }
        }
        false
    }
}
