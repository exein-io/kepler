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
