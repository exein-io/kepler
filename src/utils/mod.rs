use std::fs::File;
use std::path::Path;

use flate2::read::GzDecoder;
use log::{info, warn};
use version_compare::{CompOp, VersionCompare};

pub fn download_to_file(url: &str, file_name: &Path) -> Result<(), String> {
    info!("downloading {} to {} ...", url, file_name.display(),);

    let client = reqwest::blocking::Client::builder()
        .timeout(Some(std::time::Duration::from_secs(300)))
        .build()
        .map_err(|e| format!("could not create http client: {}", e))?;
    let mut res = client
        .get(url)
        .send()
        .map_err(|e| format!("error downloading file: {}", e))?;

    let mut file = File::create(file_name)
        .map_err(|e| format!("could not create {}: {}", file_name.display(), e))?;

    res.copy_to(&mut file)
        .map_err(|e| format!("could not download {}: {}", file_name.display(), e))?;

    Ok(())
}

pub fn gunzip(from: &Path, to: &Path) -> Result<(), String> {
    info!("extracting {} to {} ...", from.display(), to.display());

    let source =
        File::open(from).map_err(|e| format!("could not open {}: {}", from.display(), e))?;

    let mut archive = std::io::BufReader::new(GzDecoder::new(source));

    let mut dest =
        File::create(to).map_err(|e| format!("could not create {}: {}", to.display(), e))?;

    std::io::copy(&mut archive, &mut dest)
        .map_err(|e| format!("could not extract {}: {}", from.display(), e))?;

    Ok(())
}

pub fn version_cmp(a: &str, b: &str, operator: &CompOp) -> bool {
    if let Ok(res) = VersionCompare::compare_to(a, b, operator) {
        return res;
    } else {
        warn!(
            "could not compare versions {} and {} with {:?}",
            a, b, operator
        );
    }
    false
}
