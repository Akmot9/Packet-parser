// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 023 — CNS/ATM Ground Station and Service Status Reports
//! (EUROCONTROL-SPEC-0149-16) : l'etat d'une station sol ADS-B ou
//! multilateration et de ses services, en accompagnement d'un flux CAT 021.

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, TimeOfDay},
};

/// Type de rapport (I023/000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReportType {
    GroundStationStatus,
    ServiceStatus,
    ServiceStatistics,
    Other(u8),
}

impl From<u8> for ReportType {
    fn from(code: u8) -> Self {
        match code {
            1 => Self::GroundStationStatus,
            2 => Self::ServiceStatus,
            3 => Self::ServiceStatistics,
            other => Self::Other(other),
        }
    }
}

/// Type et identifiant du service (I023/015).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ServiceTypeAndIdentification {
    /// SID, quatre bits.
    pub identification: u8,
    /// STYP, quatre bits : 1 ADS-B VDL4, 2 ADS-B Ext Squitter, 3 ADS-B UAT,
    /// 4 TIS-B VDL4... (Part 16, I023/015).
    pub service_type: u8,
}

/// Etat de la station sol (I023/100).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GroundStationStatus {
    /// NOGO = 1 : donnees non utilisables en operationnel.
    pub nogo: bool,
    /// ODP : surcharge du processeur.
    pub processor_overload: bool,
    /// OXT : surcharge de l'interface sol.
    pub interface_overload: bool,
    /// MSC : systeme de surveillance connecte.
    pub monitoring_connected: bool,
    /// TSV = 1 : source de temps invalide.
    pub time_source_invalid: bool,
    /// SPO : attaque par usurpation detectee.
    pub spoofing: bool,
    /// RN : renumerotation des pistes.
    pub renumbering: bool,
    /// GSSP (second extent), periode de rapport d'etat, en secondes.
    pub reporting_period: Option<u8>,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Configuration du service (I023/101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ServiceConfiguration {
    /// RP, periode des rapports CAT 021, LSB 0,5 s.
    pub report_period: u8,
    /// SC, classe de service, trois bits.
    pub service_class: u8,
    /// SSRP (second extent), periode de rapport d'etat du service, en
    /// secondes.
    pub status_reporting_period: Option<u8>,
}

/// Les items decodes d'un record CAT 023.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StatusReport {
    pub data_source: Option<DataSourceIdentifier>,
    pub report_type: Option<ReportType>,
    pub service: Option<ServiceTypeAndIdentification>,
    /// I023/070.
    pub time_of_day: Option<TimeOfDay>,
    pub ground_station_status: Option<GroundStationStatus>,
    pub service_configuration: Option<ServiceConfiguration>,
    /// I023/200, portee operationnelle en NM.
    pub operational_range_nm: Option<u8>,
    /// I023/110, STAT (trois bits) : 0 inconnu, 1 arrete, 2 service non
    /// disponible, 3 degrade, 4 normal, 5 initialisation.
    pub service_status: Option<u8>,
    /// Nombre d'entrees de I023/120, Service Statistics.
    pub service_statistics_count: Option<u8>,
}

impl StatusReport {
    /// Decode les items typees d'un record CAT 023 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 23 {
            return None;
        }
        Some(Self {
            data_source: record
                .item("I023/010")
                .and_then(DataSourceIdentifier::from_item),
            report_type: record
                .item("I023/000")
                .and_then(|d| d.first().map(|code| ReportType::from(*code))),
            service: record.item("I023/015").and_then(|d| match d {
                [octet] => Some(ServiceTypeAndIdentification {
                    identification: octet >> 4,
                    service_type: octet & 0x0f,
                }),
                _ => None,
            }),
            time_of_day: record.item("I023/070").and_then(TimeOfDay::from_item),
            ground_station_status: record.item("I023/100").and_then(ground_station_status),
            service_configuration: record.item("I023/101").and_then(service_configuration),
            operational_range_nm: record.item("I023/200").and_then(|d| d.first().copied()),
            service_status: record
                .item("I023/110")
                .and_then(|d| d.first().map(|octet| (octet >> 1) & 0x07)),
            service_statistics_count: record.item("I023/120").and_then(|d| d.first().copied()),
        })
    }
}

fn ground_station_status(data: &[u8]) -> Option<GroundStationStatus> {
    let first = *data.first()?;
    Some(GroundStationStatus {
        nogo: first & 0x80 != 0,
        processor_overload: first & 0x40 != 0,
        interface_overload: first & 0x20 != 0,
        monitoring_connected: first & 0x10 != 0,
        time_source_invalid: first & 0x08 != 0,
        spoofing: first & 0x04 != 0,
        renumbering: first & 0x02 != 0,
        reporting_period: data.get(1).map(|octet| octet >> 1),
        raw: first,
    })
}

fn service_configuration(data: &[u8]) -> Option<ServiceConfiguration> {
    let [report_period, second, rest @ ..] = data else {
        return None;
    };
    Some(ServiceConfiguration {
        report_period: *report_period,
        service_class: second >> 5,
        status_reporting_period: rest.first().map(|octet| octet >> 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// Trames 1 et 58 de pcaps_exemple/protocols/asterix/wireshark_9953_cat021023.pcap
    /// (239.1.20.1:56610) : rapport d'etat du service ADS-B Ext Squitter,
    /// puis rapport d'etat de la station sol, recoupes avec tshark 4.6.6.
    const CAT021023_FRAME_1: &str = "170011f780930d02125d18e4020104ff08";
    const CAT021023_FRAME_58: &str = "17000cd8930d015d19640104";

    #[test]
    fn test_decodes_a_real_service_status_report_against_tshark() {
        let bytes = hex::decode(CAT021023_FRAME_1).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 1");
        let report = StatusReport::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(report.data_source.map(|d| (d.sac, d.sic)), Some((147, 13)));
        assert_eq!(report.report_type, Some(ReportType::ServiceStatus));
        assert_eq!(
            report.service,
            Some(ServiceTypeAndIdentification {
                identification: 1,
                service_type: 2,
            })
        );
        assert_eq!(
            report.time_of_day.map(TimeOfDay::seconds),
            Some(47_665.781_25)
        );
        assert_eq!(
            report.service_configuration,
            Some(ServiceConfiguration {
                report_period: 2, // 1 s
                service_class: 0,
                status_reporting_period: Some(2),
            })
        );
        assert_eq!(report.operational_range_nm, Some(255));
        assert_eq!(report.service_status, Some(4));
        assert_eq!(report.ground_station_status, None);
    }

    #[test]
    fn test_decodes_a_real_ground_station_status_against_tshark() {
        let bytes = hex::decode(CAT021023_FRAME_58).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 58");
        let report = StatusReport::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(report.report_type, Some(ReportType::GroundStationStatus));
        assert_eq!(
            report.time_of_day.map(TimeOfDay::seconds),
            Some(47_666.781_25)
        );
        let status = report.ground_station_status.unwrap();
        assert!(!status.nogo && !status.processor_overload && !status.interface_overload);
        assert!(!status.monitoring_connected && !status.time_source_invalid);
        assert!(!status.spoofing && !status.renumbering);
        assert_eq!(status.reporting_period, Some(2));
        assert_eq!(status.raw, 0x01);
        assert_eq!(report.service, None);
        assert_eq!(report.service_configuration, None);
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            StatusReport::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
