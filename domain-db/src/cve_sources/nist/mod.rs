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
// cargo test -p domain-db --features long-running-test
#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // Fixtures
    const MULTI_CVE_FIXTURE_2002: &str =
        include_str!("../../db/fixtures/multiple_nvdcve-1.1-2002.json");
    const MULTI_CVE_FIXTURE_2025: &str =
        include_str!("../../db/fixtures/multiple_nvdcve-1.1-2025.json");
    const V2_V3_FIXTURE_1999: &str = include_str!("../../db/fixtures/single_CVE-1999-0199.json");
    const V2_V3_FIXTURE_2013: &str = include_str!("../../db/fixtures/single_CVE-2013-0159.json");
    const V2_FIXTURE: &str = include_str!("../../db/fixtures/single_CVE-1999-0208.json");
    const V3_FIXTURE: &str = include_str!("../../db/fixtures/single_CVE-2025-0410.json");

    #[cfg(feature = "long-running-test")]
    const DATA_PATH: &str = "../data/";

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

    #[test_case(V2_V3_FIXTURE_1999, 9.8, "CRITICAL", Some("NETWORK"))]
    #[test_case(V2_V3_FIXTURE_2013, 7.1, "HIGH", Some("LOCAL"))]
    fn test_extract_score_severity_vector(
        fixture: &str,
        expected_score: f64,
        expected_severity: &str,
        expected_vector: Option<&str>,
    ) {
        let cve: serde_json::error::Result<cve::CVE> = serde_json::from_str(fixture);
        let actual = extract_score_severity_vector(&cve.unwrap());

        let expected = (
            expected_score,
            expected_severity.to_string(),
            expected_vector.map(|s| s.to_string()),
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_cve_container_serializaion() {
        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_str(MULTI_CVE_FIXTURE_2002);
        let cve_container = cve_container.unwrap();
        let cves: Vec<cve::CVE> = cve_container.CVE_Items.into_iter().collect();

        assert_eq!(
            cves.into_iter()
                .map(|x| x.cve.meta.id)
                .collect::<Vec<String>>(),
            vec!["CVE-1999-0001", "CVE-1999-0002", "CVE-1999-0003"]
        );
    }

    #[test_case(0, 5.0, 2.9, "MEDIUM", "NETWORK")]
    #[test_case(1, 10.0, 10.0, "HIGH", "NETWORK")]
    #[test_case(2, 10.0, 10.0, "HIGH", "NETWORK")]
    fn test_fields_score_severity_vector_v2_case(
        idx: usize,
        expected_base_score: f64,
        expected_impact_score: f32,
        expected_severity: &str,
        expected_access_vector: &str,
    ) {
        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_str(MULTI_CVE_FIXTURE_2002);
        let cve_container = cve_container.unwrap();
        let cves: Vec<cve::CVE> = cve_container.CVE_Items.into_iter().collect();

        let metric_v2 = &cves[idx].impact.metric_v2;
        let actual = metric_v2.as_ref().map(|m| {
            (
                m.cvss.base_score,
                m.impact_score,
                m.severity.as_str(),
                m.cvss.access_vector.as_str(),
            )
        });

        let expected = Some((
            expected_base_score,
            expected_impact_score,
            expected_severity,
            expected_access_vector,
        ));

        assert_eq!(actual, expected);
    }

    #[test_case(0, 4.9, 3.6, "MEDIUM", "NETWORK")]
    #[test_case(1, 7.8, 5.9, "HIGH", "LOCAL")]
    #[test_case(2, 6.5, 3.6, "MEDIUM", "NETWORK")]
    #[test_case(3, None, None, "", "")]
    fn test_fields_score_severity_vector_v3_case(
        idx: usize,
        expected_base_score: impl Into<Option<f64>>,
        expected_impact_score: impl Into<Option<f32>>,
        expected_severity: &str,
        expected_attack_vector: &str,
    ) {
        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_str(MULTI_CVE_FIXTURE_2025);
        let cve_container = cve_container.unwrap();
        let cves: Vec<cve::CVE> = cve_container.CVE_Items.into_iter().collect();

        let metric_v3 = &cves[idx].impact.metric_v3;
        let actual = metric_v3
            .as_ref()
            .map(|m| {
                (
                    Some(m.cvss.base_score),
                    Some(m.impact_score),
                    m.cvss.base_severity.as_str(),
                    m.cvss.attack_vector.as_str(),
                )
            })
            .unwrap_or((None, None, "", ""));

        let expected = (
            expected_base_score.into(),
            expected_impact_score.into(),
            expected_severity,
            expected_attack_vector,
        );

        assert_eq!(actual, expected);
    }

    #[test_case("v2", V2_FIXTURE, true, true ; "only v2")]
    #[test_case("v3", V3_FIXTURE, true, true ; "only v3")]
    #[test_case("v2v3", V2_V3_FIXTURE_1999, true, true ; "both v2 and v3")]
    fn test_impact_metric_cases(
        _case: &str,
        fixture: &str,
        expected_first: bool,
        expected_second: bool,
    ) {
        let cve: serde_json::error::Result<cve::CVE> = serde_json::from_str(fixture);
        let cve = cve.unwrap();
        let metric_v2 = &cve.impact.metric_v2;
        let metric_v3 = &cve.impact.metric_v3;

        let actual = match _case {
            "v2" => (metric_v2.is_some(), metric_v3.is_none()),
            "v3" => (metric_v2.is_none(), metric_v3.is_some()),
            "v2v3" => (metric_v2.is_some(), metric_v3.is_some()),
            _ => panic!("Unknown case"),
        };

        assert_eq!(actual, (expected_first, expected_second));
    }

    #[cfg(feature = "long-running-test")]
    #[test_case("{DATA_PATH}nvdcve-1.1-2002.json", 6768)]
    #[test_case("{DATA_PATH}nvdcve-1.1-2025.json", 12266)]
    fn test_all_cves_are_serialized_for_year(path_template: &str, expected_count: usize) {
        let path = &path_template.replace("{DATA_PATH}", DATA_PATH);
        let path = Path::new(path);
        let file = File::open(path);
        let reader = BufReader::new(file.unwrap());

        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        let cve_container = cve_container.unwrap();
        let cves_len = cve_container.CVE_Items.into_iter().len();

        assert_eq!(cves_len, expected_count);
    }

    #[cfg(feature = "long-running-test")]
    #[test_case("{DATA_PATH}nvdcve-1.1-2025.json")]
    fn test_all_complelte_cves_are_serialized_for_2025(path_template: &str) {
        let path = &path_template.replace("{DATA_PATH}", DATA_PATH);
        let path = Path::new(path);
        let file = File::open(path);
        let reader = BufReader::new(file.unwrap());
        let cve_container: serde_json::error::Result<CVEContainer> =
            serde_json::from_reader(reader);

        let cve_container = cve_container.unwrap();
        let cves_len = cve_container
            .CVE_Items
            .iter()
            .filter(|cve| cve.is_complete())
            .count();

        assert_eq!(cves_len, 3457);
    }

    #[cfg(feature = "long-running-test")]
    #[test]
    fn test_all_cves_are_serialized_from_2002_to_2025() {
        let years = 2002..=chrono::Utc::now().year();

        for year in years {
            let path = format!("{DATA_PATH}nvdcve-1.1-{}.json", year);
            let path = Path::new(&path);
            let file = File::open(path).unwrap();
            let reader = BufReader::new(file);

            let cve_container: serde_json::error::Result<CVEContainer> =
                serde_json::from_reader(reader);

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
    }
    /* Example output: (includeing "non-cmplete" CVEs)
        Expected count: 6768  | Actual count: 6768  | Path: ../data/nvdcve-1.1-2002.json
        Expected count: 1550  | Actual count: 1550  | Path: ../data/nvdcve-1.1-2003.json
        ...
    */
}
