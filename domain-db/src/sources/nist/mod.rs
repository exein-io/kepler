use std::{
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;

use crate::{
    db::{self, PostgresRepository},
    sources::download_to_file,
};

pub mod cpe;
pub mod cve;

pub const SOURCE_NAME: &str = "NIST";
pub const VERSION: &str = "1.1";

pub fn import(
    repository: &PostgresRepository,
    year: &str,
    data_path: &Path,
    refresh: bool,
) -> Result<u32> {
    let (_, mut cve_list) = download(year, data_path, refresh)?;

    log::info!("connected to database, importing records ...");

    let mut num_imported = 0;

    for item in &mut cve_list {
        let json = serde_json::to_string(item)?;

        let object_id = match repository
            .create_object_if_not_exist(db::models::NewObject::with(item.id().into(), json))
        {
            Err(e) => bail!(e),
            Ok(id) => id,
        };

        let mut refs = Vec::new();
        for data in &item.cve.references.reference_data {
            refs.push(db::models::Reference {
                url: data.url.clone(),
                tags: data.tags.clone(),
            })
        }

        for product in item.collect_unique_products() {
            let new_cve = db::models::NewCVE::with(
                SOURCE_NAME.into(),
                product.vendor,
                product.product,
                item.id().into(),
                item.summary().into(),
                item.score(),
                item.severity().into(),
                Some(item.vector().into()),
                refs.clone(),
                Some(object_id),
            );
            match repository.create_cve_if_not_exist(new_cve) {
                Err(e) => bail!(e),
                Ok(true) => num_imported += 1,
                Ok(false) => {}
            }

            if num_imported > 0 && num_imported % 100 == 0 {
                log::info!("imported {} records ...", num_imported);
            }
        }
    }

    Ok(num_imported)
}

fn download(year: &str, data_path: &Path, refresh: bool) -> Result<(PathBuf, Vec<cve::CVE>)> {
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

    let mut cves: Vec<cve::CVE> = serde_json::from_reader(reader)
        .with_context(|| format!("failed to parse cves from {}", path.as_ref().display()))?;

    // remove CVE without configurations as they're still being processed
    cves.retain(|item| item.is_complete());

    Ok(cves)
}
