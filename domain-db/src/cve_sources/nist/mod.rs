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
pub const VERSION: &str = "2.0";

pub fn download(year: u16, data_path: &Path, refresh: bool) -> Result<(PathBuf, Vec<cve::CVE>)> {
    let mut file_name = data_path.to_path_buf();
    file_name.push(format!("nvdcve-{VERSION}-{year}.json"));

    let mut gzip_file_name = data_path.to_path_buf();
    gzip_file_name.push(format!("nvdcve-{VERSION}-{year}.json.gz"));

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
                "https://nvd.nist.gov/feeds/json/cve/{VERSION}/nvdcve-{VERSION}-{year}.json.gz"
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

    let resp: NvdResponse = serde_json::from_reader(reader)
        .with_context(|| format!("failed to parse cve file from {}", path.as_ref().display()))?;

    let cves = resp
        .vulnerabilities
        .into_iter()
        .map(|v| v.cve)
        .filter(|cve| cve.is_complete())
        .collect();

    Ok(cves)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdResponse {
    #[serde(default)]
    pub results_per_page: Option<u32>,
    #[serde(default)]
    pub start_index: Option<u32>,
    #[serde(default)]
    pub total_results: Option<u64>,
    pub vulnerabilities: Vec<VulnerabilityItem>,
}

#[derive(Debug, Deserialize)]
pub struct VulnerabilityItem {
    pub cve: cve::CVE,
}

// cargo test -p domain-db --lib -- --nocapture
// cargo test -p domain-db --features long-running-test
#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // Fixtures
    const MULTI_CVE_FIXTURE_2002: &str = include_str!("../../db/fixtures/nvdcve-2.0-2002.json");
    const MULTI_CVE_FIXTURE_2025: &str = include_str!("../../db/fixtures/nvdcve-2.0-2025.json");
    const V2_V3_FIXTURE_2025: &str =
        include_str!("../../db/fixtures/allMetrics_CVE-2025-0168.json");

    #[test]
    fn test_nvd_response_serialization() {
        let resp: serde_json::error::Result<NvdResponse> =
            serde_json::from_str(MULTI_CVE_FIXTURE_2002);
        let resp = resp.unwrap();
        let cves: Vec<cve::CVE> = resp.vulnerabilities.into_iter().map(|v| v.cve).collect();

        assert_eq!(
            cves.into_iter().map(|x| x.id).collect::<Vec<String>>()[..3],
            vec!["CVE-1999-0095", "CVE-1999-0082", "CVE-1999-1471"]
        );
    }

    #[test_case(0, 10.0, 10.0, "HIGH", "NETWORK")]
    #[test_case(2, 7.2, 10.0, "HIGH", "LOCAL")]
    #[test_case(3, 4.6, 6.4, "MEDIUM", "LOCAL")]
    fn test_fields_score_severity_vector_v2_case(
        idx: usize,
        expected_base_score: f64,
        expected_impact_score: f32,
        expected_severity: &str,
        expected_vector: &str,
    ) {
        let resp: serde_json::error::Result<NvdResponse> =
            serde_json::from_str(MULTI_CVE_FIXTURE_2002);
        let resp = resp.unwrap();
        let cves: Vec<cve::CVE> = resp.vulnerabilities.into_iter().map(|v| v.cve).collect();

        let metric_v2 = cves[idx].metrics.as_ref().and_then(|m| m.v2.first());

        let actual = metric_v2.map(|m| {
            let base = m.data.base_score;
            let impact = m.impact_score.unwrap_or_default();

            let severity = m.base_severity.clone().unwrap();

            let vector = m.data.access_vector.clone().unwrap();

            (base, impact, severity, vector)
        });

        let expected = Some((
            expected_base_score,
            expected_impact_score,
            expected_severity.to_string(),
            expected_vector.to_string(),
        ));

        assert_eq!(actual, expected);
    }

    #[test_case(0, 7.5, 3.6, "HIGH", "NETWORK")]
    #[test_case(1, 4.3, 1.4, "MEDIUM", "NETWORK")]
    #[test_case(5, 6.5, 3.6, "MEDIUM", "NETWORK")]
    fn test_fields_score_severity_vector_v3_case(
        idx: usize,
        expected_base_score: impl Into<Option<f64>>,
        expected_impact_score: impl Into<Option<f32>>,
        expected_severity: &str,
        expected_attack_vector: &str,
    ) {
        let resp: NvdResponse = serde_json::from_str(MULTI_CVE_FIXTURE_2025).unwrap();
        let cves: Vec<cve::CVE> = resp.vulnerabilities.into_iter().map(|v| v.cve).collect();

        // Prefer NVD "Primary", else first v3.1
        let m = cves[idx]
            .metrics
            .as_ref()
            .and_then(|mm| {
                mm.v31
                    .iter()
                    .find(|x| {
                        x.metric_type.as_deref() == Some("Primary")
                            && x.source.as_deref() == Some("nvd@nist.gov")
                    })
                    .or_else(|| mm.v31.first())
            })
            .expect("no v3.1 metrics");

        let actual = (
            Some(m.data.base_score),
            m.impact_score,
            m.data.base_severity.as_str(),
            m.data.attack_vector.as_deref().unwrap_or("UNKNOWN"),
        );
        let expected = (
            expected_base_score.into(),
            expected_impact_score.into(),
            expected_severity,
            expected_attack_vector,
        );

        assert_eq!(actual, expected);
    }

    use serde::Deserialize;

    #[derive(Deserialize)]
    struct SingleCve {
        pub cve: cve::CVE,
    }

    #[test]
    fn test_extract_prefers_v40_when_all_present() {
        // Fixture must contain both cvssMetricV31 and cvssMetricV2 under metrics
        let single: SingleCve = serde_json::from_str(V2_V3_FIXTURE_2025).unwrap();
        //let (score, severity, vector) = single.cve.extract_cve_score_severity_vector();

        // Expected values should match the v4.0 'Primary' metric in the fixture
        let n = single.cve.best_cvss_norm().expect("no metrics");
        assert_eq!(n.base_score, 5.3);
        assert_eq!(n.base_severity, "MEDIUM");
        assert_eq!(n.attack_vector.as_deref(), Some("NETWORK"));

        // Cross-check: wrapper returns the same
        let t = single.cve.extract_cve_score_severity_vector();
        assert_eq!(
            t,
            (
                n.base_score,
                n.base_severity.clone(),
                n.attack_vector.clone()
            )
        );
    }

    // ---------- Long-running tests (optional) ----------

    #[cfg(feature = "long-running-test")]
    const DATA_PATH: &str = "../data/";

    #[cfg(feature = "long-running-test")]
    use chrono::Datelike;
    #[cfg(feature = "long-running-test")]
    use std::{fs::File, io::BufReader, path::Path};

    #[cfg(feature = "long-running-test")]
    use super::NvdResponse;

    #[cfg(feature = "long-running-test")]
    #[test_case("{DATA_PATH}nvdcve-2.0-2002.json")]
    #[test_case("{DATA_PATH}nvdcve-2.0-2025.json")]
    fn test_all_cves_are_serialized_for_year(path_template: &str) {
        let path = &path_template.replace("{DATA_PATH}", DATA_PATH);
        let path = Path::new(path);
        let file = File::open(path).expect("open feed");
        let reader = BufReader::new(file);

        let resp: NvdResponse = serde_json::from_reader(reader).expect("parse feed");
        let cves_len = resp.vulnerabilities.len();

        assert!(cves_len > 0, "no CVEs parsed from {}", path.display());
    }

    #[cfg(feature = "long-running-test")]
    #[test_case("{DATA_PATH}nvdcve-2.0-2025.json")]
    fn test_all_complete_cves_are_serialized_for_2025(path_template: &str) {
        let path = &path_template.replace("{DATA_PATH}", DATA_PATH);
        let path = Path::new(path);
        let file = File::open(path).expect("open feed");
        let reader = BufReader::new(file);

        let resp: NvdResponse = serde_json::from_reader(reader).expect("parse feed");
        let complete = resp
            .vulnerabilities
            .iter()
            .map(|v| &v.cve)
            .filter(|cve| cve.is_complete())
            .count();

        assert!(complete > 0, "no complete CVEs found in {}", path.display());
    }

    #[cfg(feature = "long-running-test")]
    #[test]
    fn test_all_cves_are_serialized_from_2002_to_current_year() {
        let years = 2002..=chrono::Utc::now().year();

        for year in years {
            let path = format!("{DATA_PATH}nvdcve-2.0-{year}.json");
            let path = Path::new(&path);
            let file = File::open(path).expect("open feed");
            let reader = BufReader::new(file);

            let resp: NvdResponse = serde_json::from_reader(reader).expect("parse feed");
            let count = resp.vulnerabilities.len();

            println!("Parsed count: {} | Path: {}", count, path.display());
            assert!(count > 0, "no CVEs parsed from {}", path.display());
        }
    }
}
