use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub mod node;

/// Meta contains metadata about the [`CVE`]., such as its ID and assigner.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Meta {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "ASSIGNER")]
    pub assigner: Option<String>,
}

/// Reference represents a reference to additional information about the [`CVE`], such as a URL and tags.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Reference {
    pub url: String,
    pub name: String,
    pub tags: Vec<String>,
}

/// References contains a list of [`Reference`]s for a [`CVE`].
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

/// ProblemType represents the type of problem associated with a [`CVE`]., including descriptions in various languages.
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

/// CvssMetricV2 object is optional.
/// As of July 2022, the NVD no longer generates new information for CVSS v2.
/// Existing CVSS v2 information will remain in the database but the NVD will no longer actively populate CVSS v2 for new CVEs.
///
/// Example json
/// ```json
///   "baseMetricV2": {
///     "cvssV2": {
///       "version": "2.0",
///       "vectorString": "AV:L/AC:L/Au:N/C:N/I:P/A:P",
///       "accessVector": "LOCAL",
///       "accessComplexity": "LOW",
///       "authentication": "NONE",
///       "confidentialityImpact": "NONE",
///       "integrityImpact": "PARTIAL",
///       "availabilityImpact": "PARTIAL",
///       "baseScore": 3.6
///     },
///     "severity": "LOW",
///     "exploitabilityScore": 3.9,
///     "impactScore": 4.9,
///     "acInsufInfo": true,
///     "obtainAllPrivilege": false,
///     "obtainUserPrivilege": false,
///     "obtainOtherPrivilege": false,
///     "userInteractionRequired": false
///   }
/// }
/// ```
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

/// CvssMetricV3 object is optional.
/// CVSSv3.0 was released in 2016, thus most [`CVE`] published before 2016 do not include the [`CVSSV3`] object.
/// The exception are [`CVE`] published before 2016 that were later reanalyzed or modified.
///
/// Example json
/// ```json
/// {
///   "baseMetricV3": {
///     "cvssV3": {
///       "version": "3.0",
///       "vectorString": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
///       "attackVector": "LOCAL",
///       "attackComplexity": "LOW",
///       "privilegesRequired": "LOW",
///       "userInteraction": "NONE",
///       "scope": "UNCHANGED",
///       "confidentialityImpact": "NONE",
///       "integrityImpact": "HIGH",
///       "availabilityImpact": "HIGH",
///       "baseScore": 7.1,
///       "baseSeverity": "HIGH"
///     },
///     "exploitabilityScore": 1.8,
///     "impactScore": 5.2
///   },
/// ```
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

/// [`ImpactMetricV2`] is used to represent the [`Impact`] metrics for [`CVE`]. records in [`CVSSV2`]. format.
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

/// [`ImpactMetricV3`] is used to represent the [`Impact`] metrics for [`CVE`] records in [`CVSSV3`] format.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImpactMetricV3 {
    #[serde(rename = "cvssV3")]
    pub cvss: CVSSV3,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: f32,
    #[serde(rename = "impactScore")]
    pub impact_score: f32,
}

/// [`Impact`] is used to represent the impact of a [`CVE`] record, which can include both [`ImpactMetricV2`] and [`ImpactMetricV3`] metrics.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Impact {
    #[serde(rename = "baseMetricV2")]
    pub metric_v2: Option<ImpactMetricV2>,
    #[serde(rename = "baseMetricV3")]
    pub metric_v3: Option<ImpactMetricV3>,
}

/// [`Configurations`] holds the nodes that describe the affected products and versions for a [`CVE`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configurations {
    #[serde(rename = "CVE_data_version")]
    pub data_version: String,
    pub nodes: Vec<node::Node>,
}

/// Common Vulnerabilities and Exposures [`CVE`] record from the NIST database.
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

    pub fn extract_cve_score_severity_vector(&self) -> (f64, String, Option<String>) {
        if let Some(v3) = self.impact.metric_v3.as_ref() {
            let score = v3.cvss.base_score;
            let severity = v3.cvss.base_severity.clone();
            let vector = Some(v3.cvss.attack_vector.clone());
            (score, severity, vector)
        } else if let Some(v2) = self.impact.metric_v2.as_ref() {
            let score = v2.cvss.base_score;
            let severity = v2.severity.clone();
            let vector = Some(v2.cvss.access_vector.clone());
            (score, severity, vector)
        } else {
            (0.0, "".to_string(), None)
        }
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
