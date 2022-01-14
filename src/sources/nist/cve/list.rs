use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::Deserialize;

// use super::cpe;
use super::item;

#[derive(Debug, Default, Deserialize)]
pub struct List {
    #[serde(rename = "CVE_Items")]
    pub items: Vec<item::CVE>,
}

impl List {
    pub fn parse(file_name: &Path) -> Result<Self, String> {
        let file = File::open(&file_name).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);
        let mut list: Self = serde_json::from_reader(reader).map_err(|e| e.to_string())?;

        // remove CVE without configurations as they're still being processed
        list.items.retain(|item| item.is_complete());

        Ok(list)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    /*
    pub fn collect_unique_products(&self) -> Vec<cpe::Product> {
        let mut products = vec![];

        for item in &self.items {
            for prod in item.collect_unique_products() {
                if !products.contains(&prod) {
                    products.push(prod);
                }
            }
        }

        products
    }
    */
}
