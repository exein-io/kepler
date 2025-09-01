use std::{collections::HashSet, fmt, str::FromStr};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use version_compare::Cmp;

use crate::cve_sources::version_cmp;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Node {
    #[serde(default)]
    pub operator: Option<Operator>,
    #[serde(default)]
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
    #[serde(default, rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(default, rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(default, rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(default, rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
    #[serde(default, rename = "matchCriteriaId")]
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
        if !self.vulnerable {
            return false;
        }
        if cpe23_product_match(&self.cpe23, product) {
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

    let my_product = if let cpe::component::Component::Value(software) = &cpe.target_sw {
        // if target_sw is set to a value, then the product name must be created from it
        // plus the actual product, so that if target_sw=node.js and pruduct=tar (<-- this
        // one alone would false positive on gnu tar for instance), my_product becomes node-tar
        format!("{}-{}", normalize_target_software(software), cpe.product)
    } else {
        cpe.product.to_string()
    };

    product == my_product
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
            match op {
                Operator::Or => self.cpe_match.iter().any(|m| m.is_match(product, version)),
                Operator::And => self.cpe_match.iter().all(|m| m.is_match(product, version)),
            }
        } else {
            match op {
                Operator::Or => self.children.iter().any(|c| c.is_match(product, version)),
                Operator::And => self.children.iter().all(|c| c.is_match(product, version)),
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
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("CPE 2.3 string")
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
    use super::{cpe23_product_match, cpe23_version_match};
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
            ProductMatch("tar", false),
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
}
