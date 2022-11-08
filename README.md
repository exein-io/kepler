<div align="center">
    <img width="300" src="res/kepler-logo.png" alt="Kepler logo">
 
  <p>
    <a href="https://github.com/Exein-io/kepler/actions/workflows/test.yml">
      <img src="https://github.com/Exein-io/kepler/actions/workflows/test.yml/badge.svg?branch=main" alt="Lint and Tests">
    </a>
    <a href="https://opensource.org/licenses/Apache-2.0">
      <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
    </a>
  </p>
</div>

<br/>

Kepler is a vulnerability database and lookup store and API currently utilising [National Vulnerability Database](https://nvd.nist.gov/) and [NPM Advisories](https://npmjs.org/) as data sources; implementing CPE 2.3 tree expressions and version range evaluation in realtime.

<br/>

# Setup

## Docker (recommended)

We provide a docker bundle with `kepler`, dedicated PostgreSQL database and [Ofelia](https://github.com/mcuadros/ofelia) as job scheduler for continuous update

```bash
docker compose build
docker compose up
```

### Database migration notes
When the application starts checks for pending database migrations and automatically applies them. Remove the `--migrate` option to stop when a pending migration is detected

## Build from sources

Alternatively you can build `kepler` from sources. To build you need `rust`, `cargo` and `libpg-dev` (or equivalent PostgreSQL library for your Linux distribution)

```
cargo build --release
```

# Data sources

The system will automatically fetch and import new records every 3 hours if you use our [bundle](#docker-recommended), while historical data must be imported manually.

Kepler currently supports two data sources, [National Vulnerability Database](https://nvd.nist.gov/) and [NPM Advisories](https://npmjs.org/). You can import the data sources historically as follows.

## NIST Data

To import NIST records from all available years (2002 to 2022):

```bash
for year in $(seq 2002 2022); do 
    docker run --rm -v $(pwd)/data:/data \
        -e DATABASE_URL=postgres://kepler:kepler@localhost:5432/kepler \
	--network=kepler_default \
	kepler:dev import_nist $year -d /data; 
done 
```

The system will automatically fetch and import new records records every 3 hours. 

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
