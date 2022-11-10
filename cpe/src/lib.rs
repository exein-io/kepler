use std::{fmt, str::FromStr};

use serde::Serialize;

pub mod component;
pub mod types;

use component::Component;
use types::CpeType;

#[derive(Debug, PartialEq, Eq, Serialize, Hash)]
pub struct Product {
    pub vendor: String,
    pub product: String,
}

#[derive(Debug, Clone)]
pub struct CPE23 {
    pub what: CpeType,
    pub vendor: Component,
    pub product: Component,
    pub version: Component,
    pub update: Component,
    pub edition: Component,
    pub language: Component,
    pub sw_edition: Component,
    pub target_sw: Component,
    pub target_hw: Component,
    pub other: Component,
}

impl TryFrom<&str> for CPE23 {
    type Error = String;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        CPE23::from_str(val)
    }
}

impl FromStr for CPE23 {
    type Err = String;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let uri = match uri.strip_prefix("cpe:2.3:") {
            Some(u) => u,
            None => return Err("invalid prefix".to_string()),
        };

        let mut components = uri.split(':');

        let what = if let Some(part) = components.next() {
            CpeType::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let vendor = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let product = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let version = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let update = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let edition = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let language = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let sw_edition = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let target_sw = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let target_hw = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let other = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };

        Ok(Self {
            what,
            vendor,
            product,
            version,
            update,
            edition,
            language,
            sw_edition,
            target_sw,
            target_hw,
            other,
        })
    }
}

impl fmt::Display for CPE23 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            what,
            vendor,
            product,
            version,
            update,
            edition,
            language,
            sw_edition,
            target_sw,
            target_hw,
            other,
        } = self;

        write!(f, "cpe:2.3:{what:#}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CPE23;

    #[test]
    fn can_parse_valid_strings() {
        // cat nvdcve-1.1-2021.json| grep "cpe:2\.3" | sort -u | cut -d'"' -f 4 | shuf -n50
        let valid_cpes = vec![
            "cpe:2.3:o:intel:xeon_w-11865mle_firmware:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:dell:vostro_3888:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:yeastar:neogate_tg400:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:mitsubishielectric:rv13fr:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:wayfair:git-parse:*:*:*:*:*:node.js:*:*",
            "cpe:2.3:h:siemens:ruggedcom_rsg2100:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:google:android:4.2.2:*:*:*:*:*:*:*",
            "cpe:2.3:h:intel:xeon_e7-8894_v4:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:dell:vostro_15_5510:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:pomerium:pomerium:*:*:*:*:*:*:*:*",
            "cpe:2.3:h:intel:xeon_w-1290t:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:nvidia:jetson_nano:-:*:-:*:*:*:*:*",
            "cpe:2.3:o:intel:xeon_d-1528_firmware:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:synology:calendar:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:zohocorp:manageengine_log360:5.2:build5211:*:*:*:*:*:*",
            "cpe:2.3:h:sonicwall:sma_210:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:dlink:dap-2695_firmware:1.17.rc063:*:*:*:*:*:*:*",
            "cpe:2.3:h:nvidia:jetson_tx1:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:paloaltonetworks:prisma_cloud:20.09:-:*:*:compute:*:*:*",
            "cpe:2.3:a:elementary:switchboard_bluetooth_plug:*:*:*:*:*:elementary_os:*:*",
            "cpe:2.3:h:intel:xeon_w-1290e:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:intel:xeon_w-3235:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:cisco:ios_xe:3.6.9e:*:*:*:*:*:*:*",
            "cpe:2.3:o:intel:xeon_w-2123_firmware:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:sap:netweaver:7.10:*:*:*:*:*:*:*",
            "cpe:2.3:o:intel:lapbc510_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:h:intel:core_i7-11700t:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:care2x:hospital_information_management_system:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:zohocorp:manageengine_key_manager_plus:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:hitachiabb-powergrids:counterparty_settlement_and_billing:*:*:*:*:*:*:*:*",
            "cpe:2.3:h:dell:poweredge_mx740c:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:zohocorp:manageengine_adselfservice_plus:5.0:5030:*:*:*:*:*:*",
            "cpe:2.3:h:asus:rs520-e9-rs8:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:freebsd:freebsd:12.2:p2:*:*:*:*:*:*",
            "cpe:2.3:a:ovation:dynamic_content:1.10.1:*:*:*:*:elementor:*:*",
            "cpe:2.3:h:weidmueller:uc20-wl2000-ac:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:nxp:lpc5516jev98_firmware:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:huawei:s1700_firmware:v200r010c00spc300:*:*:*:*:*:*:*",
            "cpe:2.3:a:vmware:vcenter_server:6.5:update3k:*:*:*:*:*:*",
            "cpe:2.3:a:f-secure:atlant:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:wago:750-8213_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:qualcomm:qcn6024_firmware:-:*:*:*:*:*:*:*",
            "cpe:2.3:h:samsung:ml-6510_sv901a:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:cisco:ucs-e180d-m2_firmware:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:zohocorp:manageengine_servicedesk_plus:9.1:9101:*:*:*:*:*:*",
            "cpe:2.3:h:asus:rt-ax55:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:open-xchange:open-xchange_appsuite:7.10.3:rev19:*:*:*:*:*:*",
            "cpe:2.3:a:thinkjs:think-helper:*:*:*:*:*:node.js:*:*",
            "cpe:2.3:o:juniper:junos:16.1:r7:*:*:*:*:*:*",
            "cpe:2.3:h:citrix:mpx\\/sdx_14060_fips:-:*:*:*:*:*:*:*",
        ];

        for s in valid_cpes {
            let res = s.parse::<CPE23>();
            assert!(res.is_ok());
            assert_eq!(s, res.unwrap().to_string())
        }
    }

    #[test]
    fn can_detect_invalid_strings() {
        let invalid_cpes = vec![
            "trollololol",
            ":::",
            ":-:-;",
            "--__--,",
            "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*",
            "cpo:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
            "cpe:2.2:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
        ];

        for s in invalid_cpes {
            let res = s.parse::<CPE23>();

            assert!(res.is_err());
        }
    }
}
