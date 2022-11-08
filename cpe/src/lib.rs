use std::str::FromStr;

use serde::Serialize;

pub mod component;
pub mod types;

use component::Component;
use types::Type;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Product {
    pub vendor: String,
    pub product: String,
}

#[derive(Debug, Clone)]
pub struct CPE23 {
    pub what: Type,
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

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let mut iter = val.splitn(13, ':');
        let (
            cpe,
            ver,
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
        ) = (
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
            iter.next().ok_or("invalid version string")?,
        );

        if cpe != "cpe" && cpe != "CPE" {
            return Err(format!("expected 'cpe' found '{}'", cpe));
        } else if ver != "2.3" {
            return Err(format!("expected cpe v2.3, found v{}", ver));
        }

        let what = Type::try_from(what)?;
        let vendor = Component::try_from(vendor)?;
        let product = Component::try_from(product)?;
        let version = Component::try_from(version)?;
        let update = Component::try_from(update)?;
        let edition = Component::try_from(edition)?;
        let language = Component::try_from(language)?;
        let sw_edition = Component::try_from(sw_edition)?;
        let target_sw = Component::try_from(target_sw)?;
        let target_hw = Component::try_from(target_hw)?;
        let other = Component::try_from(other)?;

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

#[cfg(test)]
mod tests {
    use super::CPE23;
    use std::collections::HashMap;

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
        }
    }

    #[test]
    fn can_detect_invalid_strings() {
        let mut invalid_cpes = HashMap::new();

        invalid_cpes.insert("trollololol", "invalid version string");
        invalid_cpes.insert(":::", "invalid version string");
        invalid_cpes.insert(":-:-;", "invalid version string");
        invalid_cpes.insert("--__--,", "invalid version string");
        invalid_cpes.insert(
            "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*",
            "invalid version string",
        );
        invalid_cpes.insert(
            "cpo:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
            "expected 'cpe' found 'cpo'",
        );
        invalid_cpes.insert(
            "cpe:2.2:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
            "expected cpe v2.3, found v2.2",
        );
        for (s, err) in invalid_cpes {
            let res = s.parse::<CPE23>();

            assert!(res.is_err());
            assert_eq!(err, res.err().unwrap());
        }
    }
}
