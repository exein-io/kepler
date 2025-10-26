use std::{collections::HashSet, fmt, str::FromStr};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use version_compare::Cmp;

use crate::cve_sources::version_cmp;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Node {
    pub operator: Option<Operator>,
    pub negate: Option<bool>,
    #[serde(rename = "cpeMatch", default)]
    pub cpe_match: Vec<CpeMatch>,
    #[serde(default)]
    pub children: Vec<Node>,
}

// 2.0: each entry is a CPE match with version bounds and a `criteria` field (CPE 2.3 URI).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CpeMatch {
    pub vulnerable: bool,
    #[serde(
        rename = "criteria",
        deserialize_with = "cpe23_string_deserialize",
        serialize_with = "cpe23_string_serialize"
    )]
    pub cpe23: cpe::CPE23,
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
    #[serde(rename = "matchCriteriaId")]
    pub match_criteria_id: Option<String>,
}

impl CpeMatch {
    fn has_version_range(&self) -> bool {
        self.version_start_including.is_some()
            || self.version_start_excluding.is_some()
            || self.version_end_including.is_some()
            || self.version_end_excluding.is_some()
    }

    fn version_range_matches(&self, ver: &str) -> bool {
        if self
            .version_start_including
            .as_ref()
            .is_some_and(|start_inc| !version_cmp(ver, start_inc, Cmp::Ge))
        {
            return false;
        }
        if self
            .version_start_excluding
            .as_ref()
            .is_some_and(|start_exc| !version_cmp(ver, start_exc, Cmp::Gt))
        {
            return false;
        }
        if self
            .version_end_including
            .as_ref()
            .is_some_and(|end_inc| !version_cmp(ver, end_inc, Cmp::Le))
        {
            return false;
        }
        if self
            .version_end_excluding
            .as_ref()
            .is_some_and(|end_exc| !version_cmp(ver, end_exc, Cmp::Lt))
        {
            return false;
        }
        true
    }

    pub fn product(&self) -> cpe::Product {
        cpe::Product {
            vendor: self.cpe23.vendor.to_string(),
            product: self.cpe23.product.to_string(),
        }
    }

    pub fn is_match(&self, product: &str, version: &str) -> bool {
        // only evaluate leaves marked as vulnerable by NVD
        if !self.vulnerable {
            return false;
        }

        // product must match
        if cpe23_product_match(&self.cpe23, product) {
            // match contains a version range
            if self.has_version_range() {
                return self.version_range_matches(version);
            }
            return cpe23_version_match(&self.cpe23, version);
        }
        false
    }
}

fn cpe23_product_match(cpe: &cpe::CPE23, product: &str) -> bool {
    if cpe.product.is_any() {
        return true;
    } else if cpe.product.is_na() {
        return false;
    }

    let base_product = cpe.product.to_string();
    if product == base_product {
        return true;
    }

    if let cpe::component::Component::Value(software) = &cpe.target_sw {
        // when target_sw is set we also expose the historic combined form (target_sw-product)
        // to maintain compatibility with existing clients.
        let normalized = normalize_target_software(software);
        let combined = format!("{}-{}", normalized, base_product);

        return product == combined;
    }

    false
}

fn cpe23_version_match(cpe: &cpe::CPE23, version: &str) -> bool {
    if cpe.version.is_any() {
        return true;
    } else if cpe.version.is_na() {
        return false;
    }
    let my_version = if cpe.update.is_value() {
        format!("{} {}", cpe.version, cpe.update)
    } else {
        cpe.version.to_string()
    };
    version_cmp(version, &my_version, Cmp::Eq)
}

fn normalize_target_software(target_sw: &str) -> String {
    let mut norm = String::new();
    for c in target_sw.chars() {
        if c.is_alphanumeric() {
            norm.push(c);
        } else {
            break;
        }
    }
    norm
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operator {
    And,
    Or,
}

impl Node {
    pub fn collect_unique_products(&self) -> HashSet<cpe::Product> {
        let locals = self.cpe_match.iter().map(|m| m.product());

        let of_children = self
            .children
            .iter()
            .flat_map(|node| node.collect_unique_products());
        locals.chain(of_children).collect()
    }

    pub fn is_match(&self, product: &str, version: &str) -> bool {
        let op = self.operator.as_ref().unwrap_or(&Operator::Or);

        let res = if !self.cpe_match.is_empty() {
            // leaf node
            match op {
                Operator::Or => self.cpe_match.iter().any(|m| m.is_match(product, version)), // any of them
                Operator::And => self.cpe_match.iter().all(|m| m.is_match(product, version)), // all of them
            }
        } else {
            // evaluate children
            match op {
                Operator::Or => self.children.iter().any(|c| c.is_match(product, version)), // any of them
                Operator::And => self.children.iter().all(|c| c.is_match(product, version)), // all of them
            }
        };

        if self.negate.unwrap_or(false) {
            !res
        } else {
            res
        }
    }
}

// Custom serde to parse/print CPE 2.3 strings from 2.0 `criteria` field.
fn cpe23_string_deserialize<'de, D>(deserializer: D) -> Result<cpe::CPE23, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringVisitor;
    impl<'de> Visitor<'de> for StringVisitor {
        type Value = cpe::CPE23;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("CPE 2.3 string")
        }
        fn visit_str<E>(self, value: &str) -> Result<cpe::CPE23, E>
        where
            E: de::Error,
        {
            cpe::CPE23::from_str(value).map_err(E::custom)
        }
    }
    deserializer.deserialize_any(StringVisitor)
}

fn cpe23_string_serialize<S>(cpe: &cpe::CPE23, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&cpe.to_string())
}

#[cfg(test)]
mod tests {
    use super::{cpe23_product_match, cpe23_version_match, CpeMatch};
    use std::collections::HashMap;

    #[test]
    fn can_match_products_correctly() {
        struct ProductMatch(&'static str, bool);
        let mut table = HashMap::new();

        table.insert(
            "cpe:2.3:o:vendor:product:-:*:*:*:*:*:*:*",
            ProductMatch("stratocaster", false),
        );

        table.insert(
            "cpe:2.3:o:gibson:lespaul:-:*:*:*:*:*:*:*",
            ProductMatch("lespaul", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:tar:-:*:*:*:*:node.js:*:*",
            ProductMatch("tar", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:tar:-:*:*:*:*:node.js:*:*",
            ProductMatch("node-tar", true),
        );

        for (s, m) in table {
            let res = s.parse::<cpe::CPE23>();
            assert!(res.is_ok());
            assert_eq!(m.1, cpe23_product_match(&res.unwrap(), m.0));
        }
    }

    #[test]
    fn can_match_versions_correctly() {
        struct VersionMatch(&'static str, bool);
        let mut table = HashMap::new();

        table.insert(
            "cpe:2.3:o:vendor:product:-:*:*:*:*:*:*:*",
            VersionMatch("1.0.0", false),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*",
            VersionMatch("1.0.0", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*",
            VersionMatch("0.0.0", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:1:*:*:*:*:*:*:*",
            VersionMatch("1.0.0", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:1.0:*:*:*:*:*:*:*",
            VersionMatch("1.0.0", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:1.0.0:*:*:*:*:*:*:*",
            VersionMatch("1.0.0", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:1.0.1:*:*:*:*:*:*:*",
            VersionMatch("1.0.0", false),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:1.0.1:*:*:*:*:*:*:*",
            VersionMatch("1.0.1", true),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:1.0.1:rc0:*:*:*:*:*:*",
            VersionMatch("1.0.1", false),
        );

        table.insert(
            "cpe:2.3:o:vendor:product:1.0.1:rc0:*:*:*:*:*:*",
            VersionMatch("1.0.1 RC0", true),
        );

        for (s, m) in table {
            let res = s.parse::<cpe::CPE23>();
            assert!(res.is_ok());
            assert_eq!(m.1, cpe23_version_match(&res.unwrap(), m.0));
        }
    }

    #[test]
    fn version_end_excluding_treats_lower_versions_as_vulnerable() {
        let cpe = "cpe:2.3:a:elementor:site_mailer:*:*:*:*:*:*:*:*"
            .parse()
            .expect("valid CPE string");

        let matcher = CpeMatch {
            vulnerable: true,
            cpe23: cpe,
            version_start_including: None,
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("1.2.4".into()),
            match_criteria_id: None,
        };

        assert!(matcher.is_match("site_mailer", "1.2.3"));
        assert!(matcher.is_match("site_mailer", "1.0.0"));
        assert!(!matcher.is_match("site_mailer", "1.2.4"));
        assert!(!matcher.is_match("site_mailer", "1.2.5"));
    }

    #[test]
    fn target_sw_still_matches_plain_product_name() {
        let cpe = "cpe:2.3:a:elementor:site_mailer:*:*:*:*:*:wordpress:*:*"
            .parse()
            .expect("valid CPE string with target_sw");

        let matcher = CpeMatch {
            vulnerable: true,
            cpe23: cpe,
            version_start_including: None,
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("1.2.4".into()),
            match_criteria_id: None,
        };

        assert!(matcher.is_match("site_mailer", "1.2.3"));
        assert!(!matcher.is_match("site_mailer", "1.2.4"));
    }
}
