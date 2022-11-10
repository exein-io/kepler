use std::{fmt, str::FromStr};

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use version_compare::Cmp;

use crate::cve_sources::version_cmp;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Match {
    pub vulnerable: bool,
    #[serde(
        rename = "cpe23Uri",
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
}

impl Match {
    pub fn has_version_range(&self) -> bool {
        self.version_start_including.is_some()
            || self.version_start_excluding.is_some()
            || self.version_end_including.is_some()
            || self.version_end_excluding.is_some()
    }

    pub fn version_range_matches(&self, ver: &str) -> bool {
        if let Some(start_inc) = &self.version_start_including {
            if !version_cmp(ver, start_inc, Cmp::Ge) {
                return false;
            }
        }

        if let Some(start_exc) = &self.version_start_excluding {
            if !version_cmp(ver, start_exc, Cmp::Gt) {
                return false;
            }
        }

        if let Some(end_inc) = &self.version_end_including {
            if !version_cmp(ver, end_inc, Cmp::Le) {
                return false;
            }
        }

        if let Some(end_exc) = &self.version_end_excluding {
            if !version_cmp(ver, end_exc, Cmp::Lt) {
                return false;
            }
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
        // product must match
        if cpe23_product_match(&self.cpe23, product) {
            // match contains a version range
            if self.has_version_range() {
                return self.version_range_matches(version);
            }
            // comparision match on cpe23 version
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

impl Default for Operator {
    fn default() -> Self {
        Operator::Or
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Node {
    pub operator: Operator,
    pub children: Vec<Node>,
    pub cpe_match: Vec<Match>,
}

impl Node {
    pub fn collect_unique_products(&self) -> Vec<cpe::Product> {
        let mut products = vec![];

        for m in &self.cpe_match {
            let prod = m.product();
            if !products.contains(&prod) {
                products.push(prod);
            }
        }

        for child in &self.children {
            for prod in child.collect_unique_products() {
                if !products.contains(&prod) {
                    products.push(prod);
                }
            }
        }

        products
    }

    pub fn is_match(&self, product: &str, version: &str) -> bool {
        // leaf node
        if !self.cpe_match.is_empty() {
            match &self.operator {
                Operator::Or => {
                    // any of them
                    for cpe_match in &self.cpe_match {
                        if cpe_match.is_match(product, version) {
                            return true;
                        }
                    }
                }
                Operator::And => {
                    // all of them
                    for cpe_match in &self.cpe_match {
                        if !cpe_match.is_match(product, version) {
                            return false;
                        }
                    }
                    return true;
                }
            }
        } else {
            // evaluate children
            match &self.operator {
                Operator::Or => {
                    // any of them
                    for child in &self.children {
                        if child.is_match(product, version) {
                            return true;
                        }
                    }
                }
                Operator::And => {
                    // all of them
                    for child in &self.children {
                        if !child.is_match(product, version) {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }

        false
    }
}

fn cpe23_string_deserialize<'de, D>(deserializer: D) -> Result<cpe::CPE23, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringVisitor;

    impl<'de> Visitor<'de> for StringVisitor {
        type Value = cpe::CPE23;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("expected string")
        }

        fn visit_str<E>(self, value: &str) -> Result<cpe::CPE23, E>
        where
            E: de::Error,
        {
            cpe::CPE23::from_str(value).map_err(|e| E::custom(e))
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
