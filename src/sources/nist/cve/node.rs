use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use version_compare::Cmp;

use crate::sources::{nist::cpe, version_cmp};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Match {
    pub vulnerable: bool,
    #[serde(rename = "cpe23Uri")]
    pub cpe23: String,
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,

    #[serde(skip_serializing, skip_deserializing)]
    cpe: Option<cpe::CPE23>,
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

    fn parse(&mut self) -> Result<(), String> {
        if self.cpe.is_none() {
            self.cpe = Some(cpe::CPE23::try_from(self.cpe23.as_str())?);
        }
        Ok(())
    }

    pub fn product(&mut self) -> cpe::Product {
        self.parse().unwrap();
        let cpe = self.cpe.as_ref().unwrap();
        cpe::Product {
            vendor: cpe.vendor.to_string(),
            product: cpe.product.to_string(),
        }
    }

    pub fn is_match(&mut self, product: &str, version: &str) -> bool {
        self.parse().unwrap();
        let cpe = self.cpe.as_ref().unwrap();

        // product must match
        if cpe.is_product_match(product) {
            // match contains a version range
            if self.has_version_range() {
                return self.version_range_matches(version);
            }
            // comparision match on cpe23 version
            return cpe.is_version_match(version);
        }

        false
    }
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
    pub fn collect_unique_products(&mut self) -> Vec<cpe::Product> {
        let mut products = vec![];

        for m in &mut self.cpe_match {
            let prod = m.product();
            if !products.contains(&prod) {
                products.push(prod);
            }
        }

        for child in &mut self.children {
            for prod in child.collect_unique_products() {
                if !products.contains(&prod) {
                    products.push(prod);
                }
            }
        }

        products
    }

    pub fn is_match(&mut self, product: &str, version: &str) -> bool {
        // leaf node
        if !self.cpe_match.is_empty() {
            match &self.operator {
                Operator::Or => {
                    // any of them
                    for cpe_match in &mut self.cpe_match {
                        if cpe_match.is_match(product, version) {
                            return true;
                        }
                    }
                }
                Operator::And => {
                    // all of them
                    for cpe_match in &mut self.cpe_match {
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
                    for child in &mut self.children {
                        if child.is_match(product, version) {
                            return true;
                        }
                    }
                }
                Operator::And => {
                    // all of them
                    for child in &mut self.children {
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
