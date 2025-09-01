use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub mod node;

// -------------------- CVSS --------------------
// Types for NVD 2.0 metrics (v2, v3.1, v4.0).
#[derive(Debug, Serialize, Deserialize)]
pub struct Metrics {
    #[serde(default, rename = "cvssMetricV2")]
    pub v2: Vec<CvssV2Metric>,
    #[serde(default, rename = "cvssMetricV31")]
    pub v31: Vec<CvssV31Metric>,
    #[serde(default, rename = "cvssMetricV40")]
    pub v40: Vec<CvssV40Metric>,
}

/// CVSS v4.0 in NVD 2.0 lives under: `metrics.cvssMetricV40[*]`
///
/// Example (NVD 2.0):
/// ```json
/// "metrics": {
///   "cvssMetricV40": [{
///     "source": "nvd@nist.gov",
///     "type": "Primary",
///     "cvssData": {
///       "version": "4.0",
///       "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
///       "baseScore": 9.8,
///       "baseSeverity": "CRITICAL",
///       "attackVector": "NETWORK",
///     },
///     "exploitabilityScore": 3.9,
///     "impactScore": 5.9
///   }]
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssV40Metric {
    #[serde(rename = "cvssData")]
    pub data: CvssV40Data,
    pub exploitability_score: Option<f32>,
    pub impact_score: Option<f32>,
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssV40Data {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: Option<String>,
    pub attack_vector: Option<String>,
}

/// CvssMetricV3 object is optional.
/// CVSSv3.0 was released in 2016, thus most [`CVE`] published before 2016 do not include the [`CVSSV3`] object.
/// The exception are [`CVE`] published before 2016 that were later reanalyzed or modified.
///
/// Example (NVD 2.0):
/// ```json
/// "metrics": {
///   "cvssMetricV31": [{
///     "source": "nvd@nist.gov",
///     "type": "Primary",
///     "cvssData": {
///       "version": "3.1",
///       "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
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
///   }]
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV31Metric {
    #[serde(rename = "cvssData")]
    pub data: CvssV31Data,
    pub exploitability_score: Option<f32>,
    pub impact_score: Option<f32>,
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV31Data {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: String,
    pub attack_vector: Option<String>,
    pub attack_complexity: Option<String>,
    pub privileges_required: Option<String>,
    pub user_interaction: Option<String>,
    pub scope: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2Metric {
    #[serde(rename = "cvssData")]
    pub data: CvssV2Data,
    pub base_severity: Option<String>,
    pub exploitability_score: Option<f32>,
    pub impact_score: Option<f32>,
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2Data {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub access_vector: Option<String>,
    pub access_complexity: Option<String>,
    pub authentication: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
}

const NVD_SOURCE: &str = "nvd@nist.gov";

impl CvssV40Metric {
    #[inline]
    fn is_primary_nvd(&self) -> bool {
        self.metric_type.as_deref() == Some("Primary") && self.source.as_deref() == Some(NVD_SOURCE)
    }
}
impl CvssV31Metric {
    #[inline]
    fn is_primary_nvd(&self) -> bool {
        self.metric_type.as_deref() == Some("Primary") && self.source.as_deref() == Some(NVD_SOURCE)
    }
}

impl Metrics {
    #[inline]
    pub fn preferred_v40(&self) -> Option<&CvssV40Metric> {
        self.v40
            .iter()
            .find(|m| m.is_primary_nvd())
            .or_else(|| self.v40.first())
    }
    #[inline]
    pub fn preferred_v31(&self) -> Option<&CvssV31Metric> {
        self.v31
            .iter()
            .find(|m| m.is_primary_nvd())
            .or_else(|| self.v31.first())
    }
    #[inline]
    pub fn first_v2(&self) -> Option<&CvssV2Metric> {
        self.v2.first()
    }
}

/* ------------------------------ Other fields ------------------------------ */
// Other NVD 2.0 types: tags, descriptions, weaknesses, references, configurations.

#[derive(Debug, Serialize, Deserialize)]
pub struct CveTag {
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Weakness {
    pub source: String,
    #[serde(rename = "type")]
    pub weakness_type: String,
    pub description: Vec<Description>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configuration {
    #[serde(default)]
    pub nodes: Vec<node::Node>,
}

// -------------------- CVE --------------------
// Core NVD 2.0 CVE model + helpers (summary, matching, CVSS extraction).

/// Common Vulnerabilities and Exposures [`CVE`] record from the NIST database (NVD 2.0).
#[derive(Debug, Serialize, Deserialize)]
pub struct CVE {
    pub id: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: Option<String>,
    pub published: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[serde(rename = "vulnStatus")]
    pub vuln_status: Option<String>,
    #[serde(rename = "cveTags")]
    pub cve_tags: Option<Vec<CveTag>>,
    #[serde(default)]
    pub descriptions: Vec<Description>,
    pub metrics: Option<Metrics>,
    pub weaknesses: Option<Vec<Weakness>>,
    pub configurations: Option<Vec<Configuration>>,
    #[serde(default)]
    pub references: Vec<Reference>,
}

impl CVE {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn summary(&self) -> Option<&str> {
        self.descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.as_str())
    }

    pub fn problems(&self) -> Vec<&str> {
        self.weaknesses
            .as_ref()
            .map(|w| {
                w.iter()
                    .flat_map(|weakness| {
                        weakness
                            .description
                            .iter()
                            .filter(|d| d.lang == "en")
                            .map(|d| d.value.as_str())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn is_complete(&self) -> bool {
        self.configurations
            .as_ref()
            .map(|configs| configs.iter().any(|c| !c.nodes.is_empty()))
            .unwrap_or(false)
    }

    pub fn collect_unique_products(&self) -> HashSet<cpe::Product> {
        self.configurations
            .as_ref()
            .map(|configs| {
                configs
                    .iter()
                    .flat_map(|cfg| cfg.nodes.iter())
                    .flat_map(|n| n.collect_unique_products())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn is_match(&mut self, product: &str, version: &str) -> bool {
        if let Some(configs) = &mut self.configurations {
            for cfg in configs {
                for node in &mut cfg.nodes {
                    if node.is_match(product, version) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Select the best CVSS metric and return a normalized view.
    ///
    /// v4.0 Primary@NVD -> first v4.0 -> v3.1 Primary@NVD -> first v3.1 -> first v2.
    pub fn best_cvss_norm(&self) -> Option<CvssNorm> {
        let metrics = self.metrics.as_ref()?;
        if let Some(m) = metrics.preferred_v40() {
            return Some(CvssNorm::from_v40(m));
        }
        if let Some(m) = metrics.preferred_v31() {
            return Some(CvssNorm::from_v31(m));
        }
        metrics.first_v2().map(CvssNorm::from_v2)
    }

    /// Wrapper over `best_cvss_norm()`.
    /// Returns `(base_score, base_severity, attack_vector)`.
    pub fn extract_cve_score_severity_vector(&self) -> (f64, String, Option<String>) {
        self.best_cvss_norm()
            .map(|n| (n.base_score, n.base_severity, n.attack_vector))
            .unwrap_or((0.0, "NONE".to_string(), None))
    }
}

// -------------------- Normalizer --------------------
// Uniform CVSS view across versions (v2/v3.1/v4.0) for downstream use.
pub struct CvssNorm {
    pub base_score: f64,
    pub base_severity: String,
    pub vector: String,
    pub attack_vector: Option<String>,
    pub impact_score: Option<f32>,
}

impl CvssNorm {
    pub fn from_v2(m: &CvssV2Metric) -> Self {
        let sev = m
            .base_severity
            .clone()
            .unwrap_or_else(|| map_score_to_severity(m.data.base_score));

        CvssNorm {
            base_score: m.data.base_score,
            base_severity: sev,
            vector: m.data.vector_string.clone(),
            attack_vector: m.data.access_vector.clone(),
            impact_score: m.impact_score,
        }
    }

    pub fn from_v31(m: &CvssV31Metric) -> Self {
        CvssNorm {
            base_score: m.data.base_score,
            base_severity: m.data.base_severity.clone(),
            vector: m.data.vector_string.clone(),
            attack_vector: m.data.attack_vector.clone(),
            impact_score: m.impact_score,
        }
    }

    pub fn from_v40(m: &CvssV40Metric) -> Self {
        CvssNorm {
            base_score: m.data.base_score,
            base_severity: m
                .data
                .base_severity
                .clone()
                .unwrap_or_else(|| map_score_to_severity(m.data.base_score)),
            vector: m.data.vector_string.clone(),
            attack_vector: m.data.attack_vector.clone(),
            impact_score: m.impact_score,
        }
    }
}

// -------------------- Utilities --------------------
// Small helpers and score→severity mapping.

fn map_score_to_severity(score: f64) -> String {
    if score == 0.0 {
        "NONE".to_string()
    } else if score < 4.0 {
        "LOW".to_string()
    } else if score < 7.0 {
        "MEDIUM".to_string()
    } else if score < 9.0 {
        "HIGH".to_string()
    } else {
        "CRITICAL".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_complete_with_empty_configurations() {
        let cve_json = r#"{
            "id": "CVE-2025-0001",
            "published": "2025-01-01T00:00:00.000",
            "lastModified": "2025-01-01T00:00:00.000",
            "descriptions": [],
            "references": [],
            "configurations": []
        }"#;
        let cve: CVE = serde_json::from_str(cve_json).unwrap();
        assert!(!cve.is_complete());
    }

    #[test]
    fn test_is_complete_with_non_empty_nodes() {
        let cve_json = r#"{
            "id": "CVE-2025-0001",
            "published": "2025-01-01T00:00:00.000",
            "lastModified": "2025-01-01T00:00:00.000",
            "descriptions": [],
            "references": [],
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "negate": false,
                    "cpeMatch": []
                }]
            }]
        }"#;
        let cve: CVE = serde_json::from_str(cve_json).unwrap();
        assert!(cve.is_complete());
    }

    #[test]
    fn test_extract_v40_primary() {
        let cve_json = r#"{
        "id": "CVE-2025-9999",
        "published": "2025-01-01T00:00:00.000",
        "lastModified": "2025-01-02T00:00:00.000",
        "descriptions": [],
        "references": [],
        "metrics": {
            "cvssMetricV40": [{
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {
                "version": "4.0",
                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
                "attackVector": "NETWORK"
            },
            "exploitabilityScore": 3.9,
            "impactScore": 5.9
            }]
        }
        }"#;
        let cve: CVE = serde_json::from_str(cve_json).unwrap();
        let (score, sev, av) = cve.extract_cve_score_severity_vector();
        assert_eq!(score, 9.8);
        assert_eq!(sev, "CRITICAL");
        assert_eq!(av.as_deref(), Some("NETWORK"));
    }
}
