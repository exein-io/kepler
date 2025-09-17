<div align="center">
    <img width="300" src="res/kepler-logo.png" alt="Kepler logo">

  <p>
    <a href="https://github.com/Exein-io/kepler/actions/workflows/test.yaml">
      <img src="https://github.com/Exein-io/kepler/actions/workflows/test.yaml/badge.svg?branch=main" alt="Test badge">
    </a>
    <a href="https://opensource.org/licenses/Apache-2.0">
      <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
    </a>
  </p>
</div>

<br/>

Kepler is a vulnerability database and lookup store and API currently utilising [National Vulnerability Database](https://nvd.nist.gov/) as data sources; implementing CPE 2.3 tree expressions and version range evaluation in realtime.

<br/>

# Setup

When setting up `kepler` project locally you can choose either `podman` or `docker` container runtime.

## [Docker](https://docs.docker.com/engine/install/) (recommended)

We provide a docker bundle with `kepler`, dedicated PostgreSQL database and [Ofelia](https://github.com/mcuadros/ofelia) as job scheduler for continuous update

```bash
export CONTAINER_SOCKET=/var/run/docker.sock
```

```bash
docker compose build
docker-compose up
```

## [Podman](https://podman.io/docs/installation) (optional)

```bash
export CONTAINER_SOCKET=/run/user/1000/podman/podman.sock
```

```bash
podman compose build
podman-compose up
```

Or just use an alias (if you're using podman)

```
alias docker=podman
```

### Data Import and Local Testing

The `/data` directory serves as the source directory for downloading, extracting CVE JSON files and importing data into Kepler DB. When building the `kepler` image with `docker-compose.yaml`, the local `/data` directory is bound to the container:

```yaml
volumes:
  - ./data:/data:Z
```

The system supports two scenarios:

- **Pre-populated `/data`**: Contains `.gz` files for faster development setup - data is extracted and imported directly
- **Empty `/data`**: Triggers automatic download of NIST sources before extraction and import (takes longer as recent years contain large files)

This flexibility allows for reduced initial image size in deployed environments, where sources are updated frequently and downloaded as needed.

### Steps taken when testing

#### Scenario 1. Normal import (`/data` is pre-populated)

```bash
# Remove previous volumes 
docker-compose down -v

# Re-build a new image
docker compose build 

# Spin up a new kepler + kepler_db cluster   
docker-compose up

# Run the import task
for year in $(seq 2002 2025); do
  docker exec -it kepler kepler import_nist $year -d /data
done
```

**Note**

- Ensure you have removed old `/data` contents and only have v2.0 `.gz` NIST files
- Kepler doesn't automatically populate the database from `.gz` files until you explicitly run the `import_nist` command

### 2025 log output example

```ruby
[2025-09-15T09:17:46Z INFO  domain_db::cve_sources::nist] reading /data/nvdcve-2.0-2025.json ...
[2025-09-15T09:17:46Z INFO  domain_db::cve_sources::nist] loaded 11536 CVEs in 351.54686ms
[2025-09-15T09:17:46Z INFO  kepler] connected to database, importing records ...
[2025-09-15T09:17:46Z INFO  kepler] configured 'KEPLER__BATCH_SIZE' 5000
[2025-09-15T09:17:46Z INFO  kepler] 11536 CVEs pending import
[2025-09-15T09:17:47Z INFO  domain_db::db] batch imported 5000 object records ...
[2025-09-15T09:17:47Z INFO  domain_db::db] batch imported 5000 object records ...
[2025-09-15T09:17:47Z INFO  domain_db::db] batch imported 1536 object records ...
[2025-09-15T09:17:48Z INFO  kepler] batch imported 5000 cves ...
[2025-09-15T09:17:48Z INFO  kepler] batch imported 10000 cves ...
[2025-09-15T09:17:48Z INFO  kepler] batch imported 15000 cves ...
[2025-09-15T09:17:48Z INFO  kepler] batch imported 20000 cves ...
[2025-09-15T09:17:48Z INFO  kepler] batch imported 25000 cves ...
[2025-09-15T09:17:48Z INFO  kepler] batch imported 30000 cves ...
[2025-09-15T09:17:49Z INFO  kepler] batch imported 35000 cves ...
[2025-09-15T09:17:49Z INFO  kepler] imported 37592 records Total
[2025-09-15T09:17:49Z INFO  kepler] 37592 new records created
```

#### Scenario 2. Clean import (`/data` is empty)

Steps:

```bash
# 1. Delete all `.gz` files from `/data`

# 2. Destroy the existing volume where we bound populated `/data`. 
docker-compose down -v

# 3. Build a new image with an empty `/data` mount.
docker compose build

# 4. Re-trigger import (this time Kepler will download all year `.gz` files first, then proceed with `.json` extraction and database import)  

for year in $(seq 2002 2025); do
  docker exec -it kepler kepler import_nist $year -d /data
done
```

### Example output

**Notice:** The extra `downloading` step appears here compared to normal import with pre-populated `/data`.

```ruby
 for year in $(seq 2002 2025); do   podman exec -it kepler kepler import_nist $year -d /data; done

[2025-09-15T09:20:59Z INFO  domain_db::cve_sources] downloading https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2002.json.gz to /data/nvdcve-2.0-2002.json.gz ...
[2025-09-15T09:21:00Z INFO  domain_db::cve_sources::nist] extracting /data/nvdcve-2.0-2002.json.gz to /data/nvdcve-2.0-2002.json ...
[2025-09-15T09:21:00Z INFO  domain_db::cve_sources::nist] reading /data/nvdcve-2.0-2002.json ...
[2025-09-15T09:21:00Z INFO  domain_db::cve_sources::nist] loaded 6546 CVEs in 92.942702ms
[2025-09-15T09:21:00Z INFO  kepler] connected to database, importing records ...
[2025-09-15T09:21:00Z INFO  kepler] configured 'KEPLER__BATCH_SIZE' 5000
[2025-09-15T09:21:00Z INFO  kepler] 6546 CVEs pending import
[2025-09-15T09:21:01Z INFO  domain_db::db] batch imported 5000 object records ...
[2025-09-15T09:21:01Z INFO  domain_db::db] batch imported 1546 object records ...
[2025-09-15T09:21:01Z INFO  kepler] batch imported 5000 cves ...
[2025-09-15T09:21:01Z INFO  kepler] imported 9159 records Total
[2025-09-15T09:21:01Z INFO  kepler] 9159 new records created
[2025-09-15T09:21:01Z INFO  domain_db::cve_sources] downloading https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2003.json.gz to /data/nvdcve-2.0-2003.json.gz ...
[2025-09-15T09:21:02Z INFO  domain_db::cve_sources::nist] extracting /data/nvdcve-2.0-2003.json.gz to /data/nvdcve-2.0-2003.json ...
```

### 📝 Important Note: Duplicate Prevention

Kepler automatically prevents duplicate data imports through database constraints:

- **Object table**: Unique constraint on the `cve` field prevents duplicate objects
- **CVEs table**: Composite unique constraint on `(cve, vendor, product)` prevents duplicate vulnerability entries

This ensures data integrity and prevents redundant imports when running import commands multiple times.

**Database constraints source code:**
- [Object table constraint](https://github.com/exein-io/kepler/blob/72cfcbdee1f02899fc7e482b7f77cd6b4972bf6d/domain-db/src/db/mod.rs#L105)
- [CVEs table constraint](https://github.com/exein-io/kepler/blob/72cfcbdee1f02899fc7e482b7f77cd6b4972bf6d/domain-db/src/db/mod.rs#L141)
- [Migration file](https://github.com/exein-io/kepler/blob/28d7b8bb67e1b6f58038156fa909839b70965892/migrations/2025-05-15-124616_add_unique_constraint_to_objects_and_cves/up.sql)

### Database migration notes

When the application starts, it automatically checks for and applies any pending database migrations. To prevent automatic migration and stop when a pending migration is detected, remove the `--migrate` option.

# Data sources

When using our [Docker bundle](#docker-recommended), the system automatically fetches and imports new vulnerability records every 3 hours. Historical data must be imported manually using the commands below.

Kepler currently supports two data sources: [National Vulnerability Database](https://nvd.nist.gov/) and [NPM Advisories](https://npmjs.org/). Historical data can be imported using the following methods:

## NIST Data

To import NIST records from all available years (2002 to 2025):

```bash
for year in $(seq 2002 2025); do
  docker exec -it kepler kepler import_nist $year -d /data
done
```

- The system automatically fetches and imports new records every 3 hours using a scheduled `Ofelia` job

- Use the `--refresh` argument to force re-downloading from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) source

Example - Refresh data for 2025

```bash
docker exec -it kepler kepler import_nist 2025 -d /data --refresh
```

Example - Custom batch size `-e KEPLER__BATCH_SIZE`

```bash
docker exec -it -e KEPLER__BATCH_SIZE=4500 kepler kepler import_nist 2025 -d /data --refresh
```

> NOTE: Postgres supports 65535 params total so be aware when changing the default `KEPLER__BATCH_SIZE=5000` - [Postgres limits](https://www.postgresql.org/docs/current/limits.html)

---

# APIs

There are two primary APIs as of right now — the `product` API and the `cve` API detailed below.

## Products API

Products can be listed:

```bash
curl http://localhost:8000/products
```

Grouped by vendor:

```bash
curl http://localhost:8000/products/by_vendor
```

Or searched:

```bash
curl http://localhost:8000/products/search/iphone
```

## CVEs API

To use the vulnerabilities search API via cURL (prepend `node-` to the product name in order to search for NPM specific packages):

```bash
curl \
    --header "Content-Type: application/json" \
    --request POST \
    --data '{"product":"libxml2","version":"2.9.10"}' \
    http://localhost:8000/cve/search
```

Responses are cached in memory with a LRU limit of 4096 elements.

## Migration runner (diesel-cli)

If you're interested in adding new migrations you should check out and install [Diesel-cli](https://diesel.rs/guides/getting-started).

After you have `diesel-cli` [installed](https://diesel.rs/guides/getting-started#installing-diesel-cli), you can run:

```bash
diesel migration generate <name_your_migration>
```

This will generate `up.sql` and `down.sql` files which you can then apply with:

```bash
diesel migration run
```

- Or by restarting your Kepler container (this automatically triggers migrations)

## Build from sources

Alternatively, you can build Kepler from source. You'll need `rust`, `cargo`, and `libpg-dev` (or the equivalent PostgreSQL library for your Linux distribution):

```
cargo build --release
```

---

### Troubleshooting

If you get the `linking with cc` error that looks similar to this one, you're likely missing some `c` related tooling or libs.

```bash
error: linking with `cc` failed: exit status: 1
//...
= note: /usr/bin/ld: cannot find -lpq: No such file or directory
  collect2: error: ld returned 1 exit status
```

This error requires installing PostgreSQL-related C libraries:

**Fedora:**
```bash
sudo dnf install postgresql-devel
```

**Arch:**
```bash
sudo pacman -S postgresql-libs
```
