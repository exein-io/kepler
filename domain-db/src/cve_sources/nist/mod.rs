use std::{
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::Deserialize;

use crate::cve_sources::download_to_file;

pub mod cve;

pub const SOURCE_NAME: &str = "NIST";
pub const VERSION: &str = "1.1";

pub fn download(year: u16, data_path: &Path, refresh: bool) -> Result<(PathBuf, Vec<cve::CVE>)> {
    let mut file_name = data_path.to_path_buf();
    file_name.push(format!("nvdcve-{}-{}.json", VERSION, year));

    let mut gzip_file_name = data_path.to_path_buf();
    gzip_file_name.push(format!("nvdcve-{}-{}.json.gz", VERSION, year));

    if refresh {
        if gzip_file_name.exists() {
            log::info!("removing {}", gzip_file_name.display());
            fs::remove_file(&gzip_file_name)
                .with_context(|| format!("could not remove {}", gzip_file_name.display()))?;
        }

        if file_name.exists() {
            log::info!("removing {}", file_name.display());
            fs::remove_file(&file_name)
                .with_context(|| format!("could not remove {}", file_name.display()))?;
        }
    }

    if !file_name.exists() {
        if !gzip_file_name.exists() {
            let url = format!(
                "https://nvd.nist.gov/feeds/json/cve/{}/nvdcve-{}-{}.json.gz",
                VERSION, VERSION, year
            );
            download_to_file(&url, &gzip_file_name)?;
        } else {
            log::info!("found {}", gzip_file_name.display());
        }
        gunzip(&gzip_file_name, &file_name)?;
    } else {
        log::info!("found {}", file_name.display());
    }

    log::info!("reading {} ...", file_name.display());

    let start = Instant::now();
    let cve_list = read_cves_from_path(&file_name)?;

    log::info!("loaded {} CVEs in {:?}", cve_list.len(), start.elapsed());

    Ok((file_name, cve_list))
}

fn gunzip(from: &Path, to: &Path) -> Result<()> {
    log::info!("extracting {} to {} ...", from.display(), to.display());

    let source = File::open(from).with_context(|| format!("could not open {}", from.display()))?;

    let mut archive = std::io::BufReader::new(GzDecoder::new(source));

    let mut dest =
        File::create(to).with_context(|| format!("could not create {}", to.display()))?;

    std::io::copy(&mut archive, &mut dest)
        .with_context(|| format!("could not extract {}", from.display()))?;

    Ok(())
}

fn read_cves_from_path<P: AsRef<Path>>(path: P) -> Result<Vec<cve::CVE>> {
    let file = File::open(&path)
        .with_context(|| format!("failed to open file {}", path.as_ref().display()))?;

    let reader = BufReader::new(file);

    let cve_container: CVEContainer = serde_json::from_reader(reader)
        .with_context(|| format!("failed to parse cve file from {}", path.as_ref().display()))?;

    // remove CVE without configurations as they're still being processed
    let cves = cve_container
        .CVE_Items
        .into_iter()
        .filter(|item| item.is_complete())
        .collect();

    Ok(cves)
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct CVEContainer {
    pub CVE_data_type: String,
    pub CVE_data_format: String,
    pub CVE_data_version: String,
    pub CVE_data_numberOfCVEs: String,
    pub CVE_data_timestamp: String,
    pub CVE_Items: Vec<cve::CVE>,
}

// cargo test -p domain-db --lib -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    const MULTI_CVE_FIXTURE_2002: &str = "src/db/fixtures/multiple_nvdcve-1.1-2002.json";
    const MULTI_CVE_FIXTURE_2025: &str = "src/db/fixtures/multiple_nvdcve-1.1-2025.json";
    const V2_V3_FIXTURE_1999: &str = "src/db/fixtures/single_CVE-1999-0199.json";
    const V2_V3_FIXTURE_2013: &str = "src/db/fixtures/single_CVE-2013-0159.json";
    const V2_FIXTURE: &str = "src/db/fixtures/single_CVE-1999-0208.json";
    const V3_FIXTURE: &str = "src/db/fixtures/single_CVE-2025-0410.json";
    const DATA_PATH: &str = "../data/";

    // Example CVE with both v2 and v3 metrics

    // "baseMetricV3" : {
    //     "cvssV3" : {
    //       "version" : "3.0",
    //       "vectorString" : "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    //       "attackVector" : "LOCAL",
    //       "attackComplexity" : "LOW",
    //       "privilegesRequired" : "LOW",
    //       "userInteraction" : "NONE",
    //       "scope" : "UNCHANGED",
    //       "confidentialityImpact" : "NONE",
    //       "integrityImpact" : "HIGH",
    //       "availabilityImpact" : "HIGH",
    //       "baseScore" : 7.1,
    //       "baseSeverity" : "HIGH"
    //     },
    //     "exploitabilityScore" : 1.8,
    //     "impactScore" : 5.2
    //   },
    //   "baseMetricV2" : {
    //     "cvssV2" : {
    //       "version" : "2.0",
    //       "vectorString" : "AV:L/AC:L/Au:N/C:N/I:P/A:P",
    //       "accessVector" : "LOCAL",
    //       "accessComplexity" : "LOW",
    //       "authentication" : "NONE",
    //       "confidentialityImpact" : "NONE",
    //       "integrityImpact" : "PARTIAL",
    //       "availabilityImpact" : "PARTIAL",
    //       "baseScore" : 3.6
    //     },
    //     "severity" : "LOW",
    //     "exploitabilityScore" : 3.9,
    //     "impactScore" : 4.9,
    //     "acInsufInfo" : true,
    //     "obtainAllPrivilege" : false,
    //     "obtainUserPrivilege" : false,
    //     "obtainOtherPrivilege" : false,
    //     "userInteractionRequired" : false
    //   }

    fn extract_score_severity_vector(item: &cve::CVE) -> (f64, String, Option<String>) {
        if let Some(v3) = item.impact.metric_v3.as_ref() {
            let score = v3.cvss.base_score;
            let severity = v3.cvss.base_severity.clone();
            let vector = Some(v3.cvss.attack_vector.clone());
            (score, severity, vector)
        } else if let Some(v2) = item.impact.metric_v2.as_ref() {
            let score = v2.cvss.base_score;
            let severity = v2.severity.clone();
            let vector = Some(v2.cvss.access_vector.clone());
            (score, severity, vector)
        } else {
            (0.0, "".to_string(), None)
        }
    }
    #[test]
    fn test_extract_score_severity_vector() {
        let path1 = Path::new(V2_V3_FIXTURE_1999);
        let path2 = Path::new(V2_V3_FIXTURE_2013);
        let file1 = File::open(&path1);
        let file2 = File::open(&path2);

        assert_eq!(file1.is_ok(), true);
        assert_eq!(file2.is_ok(), true);

        let reader = BufReader::new(file1.unwrap());

        let cve: serde_json::error::Result<cve::CVE> = serde_json::from_reader(reader);

        assert_eq!(cve.is_ok(), true);

        let (score, severity, vector) = extract_score_severity_vector(&cve.unwrap());
        assert_eq!(
            (score, severity, vector),
            (9.8, "CRITICAL".to_string(), Some("NETWORK".to_string()))
        );

        let reader = BufReader::new(file2.unwrap());

        let cve: serde_json::error::Result<cve::CVE> = serde_json::from_reader(reader);

        assert_eq!(cve.is_ok(), true);

        let (score, severity, vector) = extract_score_severity_vector(&cve.unwrap());
        assert_eq!(
            (score, severity, vector),
            (7.1, "HIGH".to_string(), Some("LOCAL".to_string()))
        );
    }

    #[test]
    fn test_cve_container_serializaion() {
        let path = Path::new(MULTI_CVE_FIXTURE_2002);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());

        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        assert_eq!(cve_container.is_ok(), true);

        let cve_container = cve_container.unwrap();
        let cves: Vec<cve::CVE> = cve_container.CVE_Items.into_iter().collect();

        assert_eq!(cves.len(), 3);
        assert_eq!(
            cves.into_iter()
                .map(|x| x.cve.meta.id)
                .collect::<Vec<String>>(),
            vec!["CVE-1999-0001", "CVE-1999-0002", "CVE-1999-0003"]
        );
    }

    #[test]
    fn test_fields_score_severity_vector_v2() {
        let path = Path::new(MULTI_CVE_FIXTURE_2002);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());

        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        assert_eq!(cve_container.is_ok(), true);

        let cve_container = cve_container.unwrap();
        let cves: Vec<cve::CVE> = cve_container.CVE_Items.into_iter().collect();

        // First CVE
        let metric_v2 = &cves[0].impact.metric_v2;

        assert_eq!(metric_v2.is_some(), true);

        if let Some(m) = metric_v2 {
            assert_eq!(m.cvss.base_score, 5.0);
            assert_eq!(m.impact_score, 2.9);
            assert_eq!(m.severity, "MEDIUM");
            assert_eq!(m.cvss.access_vector, "NETWORK");
        }

        // Second CVE
        let metric_v2 = &cves[1].impact.metric_v2;

        if let Some(m) = metric_v2 {
            assert_eq!(m.cvss.base_score, 10.0);
            assert_eq!(m.impact_score, 10.0);
            assert_eq!(m.severity, "HIGH");
            assert_eq!(m.cvss.access_vector, "NETWORK");
        }

        // Third CVE
        let metric_v2 = &cves[2].impact.metric_v2;

        if let Some(m) = metric_v2 {
            assert_eq!(m.cvss.base_score, 10.0);
            assert_eq!(m.impact_score, 10.0);
            assert_eq!(m.severity, "HIGH");
            assert_eq!(m.cvss.access_vector, "NETWORK");
        }
    }
    #[test]
    fn test_fields_score_severity_vector_v3() {
        let path = Path::new(MULTI_CVE_FIXTURE_2025);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());

        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        assert_eq!(cve_container.is_ok(), true);

        let cve_container = cve_container.unwrap();
        let cves: Vec<cve::CVE> = cve_container.CVE_Items.into_iter().collect();

        // First CVE
        let metric_v3 = &cves[0].impact.metric_v3;
        assert_eq!(metric_v3.is_some(), true);

        if let Some(m) = metric_v3 {
            assert_eq!(m.cvss.base_score, 4.9);
            assert_eq!(m.impact_score, 3.6);
            assert_eq!(m.cvss.base_severity, "MEDIUM".to_string());
            assert_eq!(m.cvss.attack_vector, "NETWORK");
        }

        // Second CVE
        let metric_v3 = &cves[1].impact.metric_v3;
        assert_eq!(metric_v3.is_some(), true);

        if let Some(m) = metric_v3 {
            assert_eq!(m.cvss.base_score, 7.8);
            assert_eq!(m.impact_score, 5.9);
            assert_eq!(m.cvss.base_severity, "HIGH".to_string());
            assert_eq!(m.cvss.attack_vector, "LOCAL");
        }

        // Third CVE
        let metric_v3 = &cves[2].impact.metric_v3;
        assert_eq!(metric_v3.is_some(), true);

        if let Some(m) = metric_v3 {
            assert_eq!(m.cvss.base_score, 6.5);
            assert_eq!(m.impact_score, 3.6);
            assert_eq!(m.cvss.base_severity, "MEDIUM".to_string());
            assert_eq!(m.cvss.attack_vector, "NETWORK");
        }

        //Fourth CVE doesnt have metric_v3 and has empty configurations
        let metric_v3 = &cves[3].impact.metric_v3;
        let metric_v2 = &cves[3].impact.metric_v3;

        assert_eq!((metric_v3.is_none(), metric_v2.is_none()), (true, true));
    }
    #[test]
    fn test_impact_metricv2() {
        let path = Path::new(V2_FIXTURE);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());
        let cve: serde_json::error::Result<cve::CVE> = serde_json::from_reader(reader);

        assert_eq!(cve.is_ok(), true);

        let cve = cve.unwrap();
        let metric_v2 = &cve.impact.metric_v2;
        let metric_v3 = &cve.impact.metric_v3;

        assert_eq!((metric_v2.is_some(), metric_v3.is_none()), (true, true));
    }

    #[test]
    fn test_impact_metricv3() {
        let path = Path::new(V3_FIXTURE);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());
        let cve: serde_json::error::Result<cve::CVE> = serde_json::from_reader(reader);

        assert_eq!(cve.is_ok(), true);

        let cve = cve.unwrap();
        let metric_v2 = &cve.impact.metric_v2;
        let metric_v3 = &cve.impact.metric_v3;

        assert_eq!((metric_v2.is_none(), metric_v3.is_some()), (true, true));
    }

    #[test]
    fn test_impact_metricv2_and_metricv3() {
        let path = Path::new(V2_V3_FIXTURE_1999);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());

        let cve: serde_json::error::Result<cve::CVE> = serde_json::from_reader(reader);

        assert_eq!(cve.is_ok(), true);

        let cve = cve.unwrap();
        let metric_v2 = &cve.impact.metric_v2;
        let metric_v3 = &cve.impact.metric_v3;

        assert_eq!(metric_v2.is_some(), true);
        assert_eq!(metric_v3.is_some(), true);
    }

    #[test]
    #[ignore]
    fn test_all_cves_are_serialized_for_2002() {
        let path = &format!("{DATA_PATH}nvdcve-1.1-2002.json");
        let path = Path::new(path);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());

        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        assert_eq!(cve_container.is_ok(), true);

        let cve_container = cve_container.unwrap();
        let cves_len = cve_container.CVE_Items.into_iter().len();

        assert_eq!(cves_len, 6768);
    }

    #[test]
    #[ignore = "depends on when the dataset was last updated"]
    fn test_all_cves_are_serialized_for_2025() {
        let path = &format!("{DATA_PATH}nvdcve-1.1-2025.json");
        let path = Path::new(path);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());

        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        assert_eq!(cve_container.is_ok(), true);

        let cve_container = cve_container.unwrap();
        let cves_len = cve_container.CVE_Items.into_iter().len();

        assert_eq!(cves_len, 11311);
    }

    #[test]
    #[ignore = "depends on when the dataset was last updated"]
    fn test_all_cimplelte_cves_are_serialized_for_2025() {
        let path = &format!("{DATA_PATH}nvdcve-1.1-2025.json");
        let path = Path::new(path);
        let file = File::open(&path);

        assert_eq!(file.is_ok(), true);

        let reader = BufReader::new(file.unwrap());

        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        assert_eq!(cve_container.is_ok(), true);

        let cve_container = cve_container.unwrap();
        let cves_len = cve_container
            .CVE_Items
            .iter()
            .filter(|cve| cve.is_complete())
            .count();

        assert_eq!(cves_len, 2938);
    }

    #[test]
    #[ignore = "runs a bit over 1 minute"]
    fn test_all_cves_are_serialized_from_2002_to_2025() {
        let years = 2002..=chrono::Utc::now().year();

        for year in years {
            let path = format!("{DATA_PATH}nvdcve-1.1-{}.json", year);
            let path = Path::new(&path);
            let file = File::open(&path);

            assert_eq!(file.is_ok(), true);

            let reader = BufReader::new(file.unwrap());

            let cve_container: serde_json::error::Result<CVEContainer> =
                serde_json::from_reader(reader);

            assert_eq!(cve_container.is_ok(), true);
            let cve_container = cve_container.unwrap();

            let expected_len: usize = cve_container
                .CVE_data_numberOfCVEs
                .parse()
                .unwrap_or_default();

            let actual_len = cve_container.CVE_Items.into_iter().len();

            println!(
                "Expected count: {} | Actual count: {} | Path: {}",
                expected_len,
                actual_len,
                path.display()
            );

            assert_eq!(actual_len, expected_len);
        }
        /* Example output: (includeing "non-cmplete" CVEs)
            Expected count: 6768  | Actual count: 6768  | Path: ../data/nvdcve-1.1-2002.json
            Expected count: 1550  | Actual count: 1550  | Path: ../data/nvdcve-1.1-2003.json
            Expected count: 2707  | Actual count: 2707  | Path: ../data/nvdcve-1.1-2004.json
            Expected count: 4764  | Actual count: 4764  | Path: ../data/nvdcve-1.1-2005.json
            Expected count: 7140  | Actual count: 7140  | Path: ../data/nvdcve-1.1-2006.json
            Expected count: 6576  | Actual count: 6576  | Path: ../data/nvdcve-1.1-2007.json
            Expected count: 7170  | Actual count: 7170  | Path: ../data/nvdcve-1.1-2008.json
            Expected count: 5023  | Actual count: 5023  | Path: ../data/nvdcve-1.1-2009.json
            Expected count: 5189  | Actual count: 5189  | Path: ../data/nvdcve-1.1-2010.json
            Expected count: 4819  | Actual count: 4819  | Path: ../data/nvdcve-1.1-2011.json
            Expected count: 5834  | Actual count: 5834  | Path: ../data/nvdcve-1.1-2012.json
            Expected count: 6642  | Actual count: 6642  | Path: ../data/nvdcve-1.1-2013.json
            Expected count: 8846  | Actual count: 8846  | Path: ../data/nvdcve-1.1-2014.json
            Expected count: 8526  | Actual count: 8526  | Path: ../data/nvdcve-1.1-2015.json
            Expected count: 10466 | Actual count: 10466 | Path: ../data/nvdcve-1.1-2016.json
            Expected count: 16509 | Actual count: 16509 | Path: ../data/nvdcve-1.1-2017.json
            Expected count: 16591 | Actual count: 16591 | Path: ../data/nvdcve-1.1-2018.json
            Expected count: 16365 | Actual count: 16365 | Path: ../data/nvdcve-1.1-2019.json
            Expected count: 18177 | Actual count: 18177 | Path: ../data/nvdcve-1.1-2020.json
            Expected count: 10660 | Actual count: 10660 | Path: ../data/nvdcve-1.1-2021.json
            Expected count: 26247 | Actual count: 26247 | Path: ../data/nvdcve-1.1-2022.json
            Expected count: 29675 | Actual count: 29675 | Path: ../data/nvdcve-1.1-2023.json
            Expected count: 37833 | Actual count: 37833 | Path: ../data/nvdcve-1.1-2024.json
            Expected count: 11311 | Actual count: 11311 | Path: ../data/nvdcve-1.1-2025.json
        */
    }
}
