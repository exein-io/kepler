use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Instant;

use flate2::read::GzDecoder;
use log::info;

use crate::sources::download_to_file;

pub mod item;
pub mod node;

pub const VERSION: &str = "1.1";

pub fn setup(year: &str, data_path: &Path, fresh: bool) -> Result<(PathBuf, Vec<item::CVE>)> {
    let mut file_name = data_path.to_path_buf();
    file_name.push(format!("nvdcve-{}-{}.json", VERSION, year));

    let mut gzip_file_name = data_path.to_path_buf();
    gzip_file_name.push(format!("nvdcve-{}-{}.json.gz", VERSION, year));

    if fresh {
        if gzip_file_name.exists() {
            info!("removing {}", gzip_file_name.display());
            fs::remove_file(&gzip_file_name)
                .with_context(|| format!("could not remove {}", gzip_file_name.display()))?;
        }

        if file_name.exists() {
            info!("removing {}", file_name.display());
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
            info!("found {}", gzip_file_name.display());
        }
        gunzip(&gzip_file_name, &file_name)?;
    } else {
        info!("found {}", file_name.display());
    }

    info!("reading {} ...", file_name.display());

    let start = Instant::now();
    let cve_list = read_cves_from_path(&file_name)?;

    info!("loaded {} CVEs in {:?}", cve_list.len(), start.elapsed());

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

pub fn read_cves_from_path<P: AsRef<Path>>(path: P) -> Result<Vec<item::CVE>> {
    let file = File::open(&path).context("failed to open file")?;

    let reader = BufReader::new(file);

    let mut cves: Vec<item::CVE> =
        serde_json::from_reader(reader).context("failed to parse cves")?;

    // remove CVE without configurations as they're still being processed
    cves.retain(|item| item.is_complete());

    Ok(cves)
}
