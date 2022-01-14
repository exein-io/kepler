use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use version_compare::CompOp;

use crate::search::Query;
use crate::utils::version_cmp;

pub mod import;

lazy_static! {
    static ref VER_PARSER: Regex = Regex::new(r"(?P<operator>[^\d]+)(?P<version>\d.+)").unwrap();
    static ref EXPR_PARSER: Regex =
        Regex::new(r"(?P<operator>[<>=!]*)\s*(?P<version>[\d\.\-a-z]+)").unwrap();
}

pub const SOURCE_NAME: &str = "NPM";

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Person {
    pub link: Option<String>,
    pub name: String,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Metadata {
    pub module_type: String,
    pub exploitability: f64,
    pub affected_components: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Advisory {
    pub id: u32,
    pub created: String,
    pub updated: Option<String>,
    pub deleted: Option<String>,
    pub title: String,
    pub found_by: Person,
    pub reported_by: Person,
    pub module_name: String,
    pub cves: Vec<String>,
    pub vulnerable_versions: String,
    pub patched_versions: String,
    pub overview: String,
    pub recommendation: String,
    pub references: String,
    pub access: String,
    pub severity: String,
    pub cwe: String,
    pub metadata: Metadata,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Paging {
    pub next: Option<String>,
    pub prev: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Advisories {
    pub total: u32,
    pub urls: Paging,
    pub objects: Vec<Advisory>,
}

impl Advisory {
    pub fn is_match(&mut self, query: &Query) -> bool {
        // we need a version
        if let Some(version) = &query.version {
            // expr || expr || ...
            let or_expressions: Vec<&str> = self
                .vulnerable_versions
                .split("||")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();

            // any of them
            for expressions in &or_expressions {
                // all of them
                let mut passed = true;

                for captures in EXPR_PARSER.captures_iter(expressions) {
                    // normalize operator
                    let op_str = match &captures["operator"] {
                        "" => "==",
                        "=" => "==",
                        op => op,
                    };
                    // validate it
                    match CompOp::from_sign(op_str) {
                        Err(_) => {
                            warn!(
                                "can't parse npm version operator '{}' of advisory {}: {}",
                                op_str, self.id, &self.vulnerable_versions,
                            );
                            passed = false;
                            break;
                        }
                        Ok(op) => {
                            // execute the comparision
                            if !version_cmp(version, &captures["version"], &op) {
                                passed = false;
                                break;
                            }
                        }
                    }
                }

                if passed {
                    // if we are here, all of the conditions in AND passed
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Advisory;
    use crate::search::Query;

    #[test]
    fn no_match_without_version() {
        let mut adv = Advisory::default();
        adv.vulnerable_versions = "*".into();

        assert!(!adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: None,
        }));
    }

    #[test]
    fn can_match_wildcard() {
        let mut adv = Advisory::default();
        adv.vulnerable_versions = "*".into();

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("1.0.0".into()),
        }));

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("totally unrealistic but should match nevertheless".into()),
        }));
    }

    #[test]
    fn can_match_or_expressions() {
        let mut adv = Advisory::default();
        adv.vulnerable_versions = "1.0.0 || 2.0.0".into();

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("1.0.0".into()),
        }));

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("2.0.0".into()),
        }));

        assert!(!adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("3.0.0".into()),
        }));
    }

    #[test]
    fn can_match_and_expressions() {
        let mut adv = Advisory::default();
        adv.vulnerable_versions = ">1.0.0 <=2.0.0".into();

        assert!(!adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("1.0.0".into()),
        }));

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("1.0.1".into()),
        }));

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("2.0.0".into()),
        }));

        assert!(!adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("2.0.1".into()),
        }));
    }

    #[test]
    fn can_match_complex_expressions() {
        let mut adv = Advisory::default();
        adv.vulnerable_versions = "1.0.0 || 2.0.0 || >1.0.0 <=2.0.0 || 666".into();

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("1.0.0".into()),
        }));

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("2.0.0".into()),
        }));

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("1.0.1".into()),
        }));

        assert!(adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("666".into()),
        }));

        assert!(!adv.is_match(&Query {
            vendor: None,
            product: "".into(),
            version: Some("2.0.1".into()),
        }));
    }
}
