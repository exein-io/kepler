# Kepler — [![Lint and Tests](https://github.com/Exein-io/kepler/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/Exein-io/kepler/actions/workflows/test.yml) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

<img align="left" width="25%" height="25%" src="res/kepler-logo.png">

<br/>

Kepler is a vulnerability database and lookup store and API currently utilising [National Vulnerability Database](https://nvd.nist.gov/) and [NPM Advisories](https://npmjs.org/) as data sources; implementing CPE 2.3 tree expressions and version range evaluation in realtime.

<br/>

## Setup

### Pre-requisites

* `docker`;
* `rust nightly >= 1.33`;
* (optional) `python 3.x`.

### Build & run

```bash
docker compose build
docker compose up
```

While the database is running, perform the database migrations (rust and `libpg-dev` required):

```bash
export DATABASE_URL=postgres://kepler:kepler@localhost:5432/kepler

cargo install diesel_cli --no-default-features --features "postgres"
diesel migration run	
```

The system will automatically fetch and import new records every 3 hours, while historical data must be imported manually (see [importing data sources](#data-sources)).

## Data sources

Kepler currently supports two data sources, [National Vulnerability Database](https://nvd.nist.gov/) and [NPM Advisories](https://npmjs.org/). You can import the data sources historically as follows.

#### NIST Data

To import NIST records from all available years (2002 to 2022):

```bash
for year in $(seq 2002 2022); do 
    docker run -v $(pwd)/data:/data \
        -e DATABASE_URL=postgres://kepler:kepler@localhost:5432/kepler \
	--network=kepler_default \
	kepler:dev import_nist $year -d /data; 
done 
```

#### NPM Data

To import all available NPM records:

```bash
docker run -v $(pwd)/data:/data \
    -e DATABASE_URL=postgres://kepler:kepler@localhost:5432/kepler\
    --network=kepler_default \
    kepler:dev import_npm -d /data; 
```

The system will automatically fetch and import new records records every 3 hours. 

## APIs

There are two primary APIs as of right now — the `product` API and the `cve` API detailed below.

#### Products API

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

#### CVEs API

To use the vulnerabilities search API via cURL (prepend `node-` to the product name in order to search for NPM specific packages):

```bash
curl \
    --header "Content-Type: application/json" \
    --request POST \
    --data '{"product":"libxml2","version":"2.9.10"}' \
    http://localhost:8000/cve/search
```

Responses are cached in memory with a LRU limit of 4096 elements.

#### Utility

To get test and visualize the API results quickly you can use the Python utility wrappers.

```bash
pip install -r requirements-cli.txt
./kepler_cli.py linux_kernel $(uname -r)
```

It is also possible to use the CLI to see the difference in terms of CVEs between two revisions of the same software:

```bash
diff -Naur --color <(./kepler_cli.py chrome 93.0.4577.62) <(./kepler_cli.py chrome 93.0.4577.63)
```

<details>
    <summary>JSON response for query: <code>{"product":"libxml2","version":"2.9.10"}</code></summary>

    ```json
    [
        {
            "source": "NIST",
            "vendor": "xmlsoft",
            "product": "libxml2",
            "cve": "CVE-2021-3517",
            "summary": "There is a flaw in the xml entity encoding functionality of libxml2 in versions before 2.9.11. An attacker who is able to supply a crafted file to be processed by an application linked with the affected functionality of libxml2 could trigger an out-of-bounds read. The most likely impact of this flaw is to application availability, with some potential impact to confidentiality and integrity if an attacker is able to use memory information to further exploit the application.",
            "score": 7.5,
            "severity": "HIGH",
            "vector": "NETWORK",
            "references": [
                {
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1954232",
                    "tags": [
                        "Issue Tracking",
                        "Patch",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QVM4UJ3376I6ZVOYMHBNX4GY3NIV52WV/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BZOMV5J4PMZAORVT64BKLV6YIZAFDGX6/",
                    "tags": []
                },
                {
                    "url": "https://security.netapp.com/advisory/ntap-20210625-0002/",
                    "tags": []
                },
                {
                    "url": "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
                    "tags": []
                },
                {
                    "url": "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
                    "tags": []
                },
                {
                    "url": "https://security.gentoo.org/glsa/202107-05",
                    "tags": []
                }
            ]
        },
        {
            "source": "NIST",
            "vendor": "xmlsoft",
            "product": "libxml2",
            "cve": "CVE-2021-3518",
            "summary": "There's a flaw in libxml2 in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by an application linked with libxml2 could trigger a use-after-free. The greatest impact from this flaw is to confidentiality, integrity, and availability.",
            "score": 6.8,
            "severity": "MEDIUM",
            "vector": "NETWORK",
            "references": [
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QVM4UJ3376I6ZVOYMHBNX4GY3NIV52WV/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1954242",
                    "tags": [
                        "Issue Tracking",
                        "Patch",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BZOMV5J4PMZAORVT64BKLV6YIZAFDGX6/",
                    "tags": []
                },
                {
                    "url": "https://security.netapp.com/advisory/ntap-20210625-0002/",
                    "tags": []
                },
                {
                    "url": "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
                    "tags": []
                },
                {
                    "url": "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
                    "tags": []
                },
                {
                    "url": "https://security.gentoo.org/glsa/202107-05",
                    "tags": []
                },
                {
                    "url": "https://support.apple.com/kb/HT212604",
                    "tags": []
                },
                {
                    "url": "https://support.apple.com/kb/HT212605",
                    "tags": []
                },
                {
                    "url": "https://support.apple.com/kb/HT212602",
                    "tags": []
                },
                {
                    "url": "https://support.apple.com/kb/HT212601",
                    "tags": []
                },
                {
                    "url": "http://seclists.org/fulldisclosure/2021/Jul/55",
                    "tags": []
                },
                {
                    "url": "http://seclists.org/fulldisclosure/2021/Jul/54",
                    "tags": []
                },
                {
                    "url": "http://seclists.org/fulldisclosure/2021/Jul/58",
                    "tags": []
                },
                {
                    "url": "http://seclists.org/fulldisclosure/2021/Jul/59",
                    "tags": []
                }
            ]
        },
        {
            "source": "NIST",
            "vendor": "xmlsoft",
            "product": "libxml2",
            "cve": "CVE-2021-3537",
            "summary": "A vulnerability found in libxml2 in versions before 2.9.11 shows that it did not propagate errors while parsing XML mixed content, causing a NULL dereference. If an untrusted XML document was parsed in recovery mode and post-validated, the flaw could be used to crash the application. The highest threat from this vulnerability is to system availability.",
            "score": 4.3,
            "severity": "MEDIUM",
            "vector": "NETWORK",
            "references": [
                {
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1956522",
                    "tags": [
                        "Issue Tracking",
                        "Patch",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QVM4UJ3376I6ZVOYMHBNX4GY3NIV52WV/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BZOMV5J4PMZAORVT64BKLV6YIZAFDGX6/",
                    "tags": []
                },
                {
                    "url": "https://security.netapp.com/advisory/ntap-20210625-0002/",
                    "tags": []
                },
                {
                    "url": "https://security.gentoo.org/glsa/202107-05",
                    "tags": []
                }
            ]
        },
        {
            "source": "NIST",
            "vendor": "xmlsoft",
            "product": "libxml2",
            "cve": "CVE-2021-3541",
            "summary": "A flaw was found in libxml2. Exponential entity expansion attack its possible bypassing all existing protection mechanisms and leading to denial of service.",
            "score": 4.0,
            "severity": "MEDIUM",
            "vector": "NETWORK",
            "references": [
                {
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1950515",
                    "tags": [
                        "Issue Tracking",
                        "Patch",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://security.netapp.com/advisory/ntap-20210805-0007/",
                    "tags": []
                }
            ]
        },
        {
            "source": "NIST",
            "vendor": "xmlsoft",
            "product": "libxml2",
            "cve": "CVE-2019-20388",
            "summary": "xmlSchemaPreRun in xmlschemas.c in libxml2 2.9.10 allows an xmlSchemaValidateStream memory leak.",
            "score": 5.0,
            "severity": "MEDIUM",
            "vector": "NETWORK",
            "references": [
                {
                    "url": "https://gitlab.gnome.org/GNOME/libxml2/merge_requests/68",
                    "tags": [
                        "Patch",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/545SPOI3ZPPNPX4TFRIVE4JVRTJRKULL/",
                    "tags": []
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5R55ZR52RMBX24TQTWHCIWKJVRV6YAWI/",
                    "tags": []
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDPF3AAVKUAKDYFMFKSIQSVVS3EEFPQH/",
                    "tags": []
                },
                {
                    "url": "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00047.html",
                    "tags": []
                },
                {
                    "url": "https://security.netapp.com/advisory/ntap-20200702-0005/",
                    "tags": []
                },
                {
                    "url": "https://www.oracle.com/security-alerts/cpujul2020.html",
                    "tags": []
                },
                {
                    "url": "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
                    "tags": []
                },
                {
                    "url": "https://security.gentoo.org/glsa/202010-04",
                    "tags": []
                }
            ]
        },
        {
            "source": "NIST",
            "vendor": "xmlsoft",
            "product": "libxml2",
            "cve": "CVE-2020-24977",
            "summary": "GNOME project libxml2 v2.9.10 has a global buffer over-read vulnerability in xmlEncodeEntitiesInternal at libxml2/entities.c. The issue has been fixed in commit 50f06b3e.",
            "score": 6.4,
            "severity": "MEDIUM",
            "vector": "NETWORK",
            "references": [
                {
                    "url": "https://gitlab.gnome.org/GNOME/libxml2/-/issues/178",
                    "tags": [
                        "Exploit",
                        "Patch",
                        "Vendor Advisory"
                    ]
                },
                {
                    "url": "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00036.html",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2NQ5GTDYOVH26PBCPYXXMGW5ZZXWMGZC/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00061.html",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/O7MEWYKIKMV2SKMGH4IDWVU3ZGJXBCPQ/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/H3IQ7OQXBKWD3YP7HO6KCNOMLE5ZO2IR/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://security.netapp.com/advisory/ntap-20200924-0001/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7KQXOHIE3MNY3VQXEN7LDQUJNIHOVHAW/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JCHXIWR5DHYO3RSO7RAHEC6VJKXD2EH2/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/J3ICASXZI2UQYFJAOQWHSTNWGED3VXOE/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://gitlab.gnome.org/GNOME/libxml2/-/commit/50f06b3efb638efb0abd95dc62dca05ae67882c2",
                    "tags": [
                        "Patch",
                        "Vendor Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ENEHQIBMSI6TZVS35Y6I4FCTYUQDLJVP/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RIQAMBA2IJUTQG5VOP5LZVIZRNCKXHEQ/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5KTUAGDLEHTH6HU66HBFAFTSQ3OKRAN3/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/674LQPJO2P2XTBTREFR5LOZMBTZ4PZAY/",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772@%3Cdev.mina.apache.org%3E",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://security.gentoo.org/glsa/202107-05",
                    "tags": []
                }
            ]
        },
        {
            "source": "NIST",
            "vendor": "xmlsoft",
            "product": "libxml2",
            "cve": "CVE-2020-7595",
            "summary": "xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file situation.",
            "score": 5.0,
            "severity": "MEDIUM",
            "vector": "NETWORK",
            "references": [
                {
                    "url": "https://gitlab.gnome.org/GNOME/libxml2/commit/0e1a49c89076",
                    "tags": [
                        "Patch",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/545SPOI3ZPPNPX4TFRIVE4JVRTJRKULL/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://usn.ubuntu.com/4274-1/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5R55ZR52RMBX24TQTWHCIWKJVRV6YAWI/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDPF3AAVKUAKDYFMFKSIQSVVS3EEFPQH/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00047.html",
                    "tags": [
                        "Broken Link"
                    ]
                },
                {
                    "url": "https://security.netapp.com/advisory/ntap-20200702-0005/",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://www.oracle.com/security-alerts/cpujul2020.html",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
                    "tags": [
                        "Mailing List",
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://security.gentoo.org/glsa/202010-04",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://cert-portal.siemens.com/productcert/pdf/ssa-292794.pdf",
                    "tags": [
                        "Third Party Advisory"
                    ]
                },
                {
                    "url": "https://us-cert.cisa.gov/ics/advisories/icsa-21-103-08",
                    "tags": [
                        "Third Party Advisory",
                        "US Government Resource"
                    ]
                }
            ]
        }
    ]
    ```
</details>
