// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 021 — ADS-B Target Reports (EUROCONTROL-SPEC-0149-12, ed. 2.x) :
//! un rapport ADS-B par record, tel que la station sol l'a recu. Seuls les
//! items d'identification, de temps et de position sont decodes en valeurs
//! typees ; les autres restent accessibles via [`AsterixRecord::item`].

use super::{
    AsterixRecord,
    fields::{
        AircraftAddress, AircraftIdentification, DataSourceIdentifier, FlightLevel, Mode3ACode,
        TimeOfDay, sign_extend_24, track_number,
    },
};

/// Type d'adresse (I021/040, ATP, bits 8 a 6 du premier octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Adresse ICAO 24 bits.
    Icao24Bit,
    /// Adresse 24 bits duplicable.
    Duplicate,
    /// Adresse de surface d'un vehicule.
    SurfaceVehicle,
    /// Adresse anonyme.
    Anonymous,
    /// Valeur reservee.
    Reserved(u8),
}

/// Target Report Descriptor (I021/040) : premier octet, et second s'il est
/// present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TargetReportDescriptor {
    pub address_type: AddressType,
    /// ARC : resolution d'altitude (0 : 25 ft, 1 : 100 ft, 2 : inconnue).
    pub altitude_reporting_capability: u8,
    /// RC : rapport au-dela de la portee.
    pub range_check: bool,
    /// RAB : rapport issu d'un transpondeur de site.
    pub field_monitor: bool,
    /// GBS : bit sol pose (second octet, `None` s'il est absent).
    pub ground_bit: Option<bool>,
    /// SIM : cible simulee (second octet).
    pub simulated: Option<bool>,
    /// TST : cible de test (second octet).
    pub test_target: Option<bool>,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Position en coordonnees WGS-84 (I021/130), LSB 180/2^23 degres.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Wgs84Position {
    pub latitude: i32,
    pub longitude: i32,
}

impl Wgs84Position {
    pub fn latitude_deg(self) -> f64 {
        f64::from(self.latitude) * 180.0 / 8_388_608.0
    }

    pub fn longitude_deg(self) -> f64 {
        f64::from(self.longitude) * 180.0 / 8_388_608.0
    }
}

/// Position haute resolution en WGS-84 (I021/131), LSB 180/2^30 degres.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HighResolutionPosition {
    pub latitude: i32,
    pub longitude: i32,
}

impl HighResolutionPosition {
    pub fn latitude_deg(self) -> f64 {
        f64::from(self.latitude) * 180.0 / 1_073_741_824.0
    }

    pub fn longitude_deg(self) -> f64 {
        f64::from(self.longitude) * 180.0 / 1_073_741_824.0
    }
}

/// Vecteur sol en vol (I021/160).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AirborneGroundVector {
    /// RE : la vitesse depasse la plage codable.
    pub range_exceeded: bool,
    /// Vitesse sol, LSB 2^-14 NM/s.
    pub ground_speed: u16,
    /// Route, LSB 360/2^16 degres.
    pub track_angle: u16,
}

impl AirborneGroundVector {
    pub fn ground_speed_kt(self) -> f64 {
        f64::from(self.ground_speed) / 16_384.0 * 3_600.0
    }

    pub fn track_angle_deg(self) -> f64 {
        f64::from(self.track_angle) * 360.0 / 65_536.0
    }
}

/// MOPS Version (I021/210).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MopsVersion {
    /// VNS : version non supportee par la station sol.
    pub not_supported: bool,
    /// VN : 0 ED102/DO-260, 1 DO-260A, 2 ED102A/DO-260B, 3 ED102B/DO-260C.
    pub version: u8,
    /// LTT : 0 autre, 1 UAT, 2 1090 ES, 3 VDL 4.
    pub link_technology: u8,
}

/// Les items decodes d'un record CAT 021. Chaque champ est `None` quand
/// l'item est absent du FSPEC.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TargetReport {
    pub data_source: Option<DataSourceIdentifier>,
    pub descriptor: Option<TargetReportDescriptor>,
    pub track_number: Option<u16>,
    /// I021/015.
    pub service_identification: Option<u8>,
    /// I021/071.
    pub time_of_applicability_position: Option<TimeOfDay>,
    pub position: Option<Wgs84Position>,
    pub high_resolution_position: Option<HighResolutionPosition>,
    pub target_address: Option<AircraftAddress>,
    /// I021/073.
    pub time_of_message_reception_position: Option<TimeOfDay>,
    /// I021/075.
    pub time_of_message_reception_velocity: Option<TimeOfDay>,
    /// I021/077.
    pub time_of_report_transmission: Option<TimeOfDay>,
    /// Hauteur geometrique (I021/140), LSB 6.25 ft.
    pub geometric_height: Option<i16>,
    pub mops_version: Option<MopsVersion>,
    pub mode_3a: Option<Mode3ACode>,
    pub flight_level: Option<FlightLevel>,
    pub ground_vector: Option<AirborneGroundVector>,
    pub target_identification: Option<AircraftIdentification>,
    /// I021/020 : categorie d'emetteur (0 inconnue, 1 leger, ... 21
    /// vehicule de service).
    pub emitter_category: Option<u8>,
    /// I021/132, en dBm.
    pub message_amplitude: Option<i8>,
}

impl TargetReport {
    /// Decode les items typees d'un record CAT 021 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 21 {
            return None;
        }
        Some(Self {
            data_source: record
                .item("I021/010")
                .and_then(DataSourceIdentifier::from_item),
            descriptor: record.item("I021/040").and_then(descriptor),
            track_number: record.item("I021/161").and_then(track_number),
            service_identification: record.item("I021/015").and_then(|d| d.first().copied()),
            time_of_applicability_position: record.item("I021/071").and_then(TimeOfDay::from_item),
            position: record.item("I021/130").and_then(position),
            high_resolution_position: record.item("I021/131").and_then(high_resolution_position),
            target_address: record.item("I021/080").and_then(AircraftAddress::from_item),
            time_of_message_reception_position: record
                .item("I021/073")
                .and_then(TimeOfDay::from_item),
            time_of_message_reception_velocity: record
                .item("I021/075")
                .and_then(TimeOfDay::from_item),
            time_of_report_transmission: record.item("I021/077").and_then(TimeOfDay::from_item),
            geometric_height: record.item("I021/140").and_then(|d| match d {
                [high, low] => Some(i16::from_be_bytes([*high, *low])),
                _ => None,
            }),
            mops_version: record.item("I021/210").and_then(mops_version),
            mode_3a: record.item("I021/070").and_then(Mode3ACode::from_item),
            flight_level: record.item("I021/145").and_then(FlightLevel::from_item),
            ground_vector: record.item("I021/160").and_then(ground_vector),
            target_identification: record
                .item("I021/170")
                .and_then(AircraftIdentification::from_item),
            emitter_category: record.item("I021/020").and_then(|d| d.first().copied()),
            message_amplitude: record
                .item("I021/132")
                .and_then(|d| d.first().map(|amplitude| *amplitude as i8)),
        })
    }
}

fn descriptor(data: &[u8]) -> Option<TargetReportDescriptor> {
    let first = *data.first()?;
    let second = data.get(1).copied();
    Some(TargetReportDescriptor {
        address_type: match first >> 5 {
            0 => AddressType::Icao24Bit,
            1 => AddressType::Duplicate,
            2 => AddressType::SurfaceVehicle,
            3 => AddressType::Anonymous,
            other => AddressType::Reserved(other),
        },
        altitude_reporting_capability: (first >> 3) & 0x03,
        range_check: first & 0x04 != 0,
        field_monitor: first & 0x02 != 0,
        ground_bit: second.map(|octet| octet & 0x40 != 0),
        simulated: second.map(|octet| octet & 0x20 != 0),
        test_target: second.map(|octet| octet & 0x10 != 0),
        raw: first,
    })
}

fn position(data: &[u8]) -> Option<Wgs84Position> {
    match data {
        [a0, a1, a2, o0, o1, o2] => Some(Wgs84Position {
            latitude: sign_extend_24(u32::from_be_bytes([0, *a0, *a1, *a2])),
            longitude: sign_extend_24(u32::from_be_bytes([0, *o0, *o1, *o2])),
        }),
        _ => None,
    }
}

fn high_resolution_position(data: &[u8]) -> Option<HighResolutionPosition> {
    match data {
        [a0, a1, a2, a3, o0, o1, o2, o3] => Some(HighResolutionPosition {
            latitude: i32::from_be_bytes([*a0, *a1, *a2, *a3]),
            longitude: i32::from_be_bytes([*o0, *o1, *o2, *o3]),
        }),
        _ => None,
    }
}

fn mops_version(data: &[u8]) -> Option<MopsVersion> {
    let octet = *data.first()?;
    Some(MopsVersion {
        not_supported: octet & 0x40 != 0,
        version: (octet >> 3) & 0x07,
        link_technology: octet & 0x07,
    })
}

fn ground_vector(data: &[u8]) -> Option<AirborneGroundVector> {
    match data {
        [s0, s1, t0, t1] => Some(AirborneGroundVector {
            range_exceeded: s0 & 0x80 != 0,
            ground_speed: u16::from_be_bytes([s0 & 0x7f, *s1]),
            track_angle: u16::from_be_bytes([*t0, *t1]),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// `cat21_re.ast` des echantillons CroatiaControlLtd/asterix : deux data
    /// blocks CAT 021 ed. 2.x, chacun d'un record, recoupes avec tshark
    /// 4.6.6.
    const CAT021_RE: &str = concat!(
        "15002cc51d3101432304000101402bb73efa65ba0000013841763adab9f500020008cb540d0d0d0508f00162",
        "15002fc51d3101432304000101402bb73afa65b30000023841950a485a0c00021508ad5501100a0a0aff050870f140"
    );

    fn sample() -> Vec<u8> {
        hex::decode(CAT021_RE).unwrap()
    }

    #[test]
    fn test_decodes_the_public_sample_against_tshark() {
        let bytes = sample();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("cat21_re.ast decode");
        assert_eq!(packet.blocks.len(), 2);
        assert_eq!(
            packet.blocks.iter().map(|b| b.length).collect::<Vec<_>>(),
            [44, 47]
        );
        let record = &packet.blocks[0].records[0];
        let ids: Vec<&str> = record.items.iter().map(|item| item.id).collect();
        assert_eq!(
            ids,
            [
                "I021/010", "I021/040", "I021/130", "I021/080", "I021/073", "I021/074", "I021/090",
                "I021/210", "I021/020", "I021/016", "I021/132", "I021/295", "I021/RE",
            ]
        );
        // Data Ages : TRD, QI, MAM a 1.3 s ; RE de cinq octets, LEN compris.
        assert_eq!(record.item("I021/295"), Some(&[0x54, 0x0d, 0x0d, 0x0d][..]));
        assert_eq!(
            record.item("I021/RE"),
            Some(&[0x05, 0x08, 0xf0, 0x01, 0x62][..])
        );

        let report = TargetReport::from_record(record).expect("record CAT 021");
        assert_eq!(
            report.data_source,
            Some(DataSourceIdentifier { sac: 0, sic: 1 })
        );
        let descriptor = report.descriptor.unwrap();
        assert_eq!(descriptor.address_type, AddressType::Icao24Bit);
        assert_eq!(descriptor.altitude_reporting_capability, 0);
        assert_eq!(descriptor.ground_bit, Some(true));
        assert_eq!(descriptor.simulated, Some(false));
        let position = report.position.unwrap();
        assert_eq!(position.latitude_deg(), 61.475_329_399_108_89);
        assert_eq!(position.longitude_deg(), -7.878_699_302_673_34);
        assert_eq!(report.target_address, Some(AircraftAddress(1)));
        assert_eq!(
            report
                .time_of_message_reception_position
                .map(TimeOfDay::seconds),
            Some(28_802.921_875)
        );
        let mops = report.mops_version.unwrap();
        assert_eq!(
            (mops.not_supported, mops.version, mops.link_technology),
            (false, 0, 2)
        );
        assert_eq!(report.emitter_category, Some(0));
        assert_eq!(report.message_amplitude, Some(-53));
        assert_eq!(report.track_number, None);
        assert_eq!(report.target_identification, None);

        // Second record : vehicule de service (21), -83 dBm, quatre ages.
        let second = TargetReport::from_record(&packet.blocks[1].records[0]).unwrap();
        assert_eq!(second.emitter_category, Some(21));
        assert_eq!(second.message_amplitude, Some(-83));
        assert_eq!(second.target_address, Some(AircraftAddress(2)));
        assert_eq!(
            packet.blocks[1].records[0].item("I021/295"),
            Some(&[0x55, 0x01, 0x10, 0x0a, 0x0a, 0x0a, 0xff][..])
        );
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x30, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            TargetReport::from_record(&packet.blocks[0].records[0]),
            None
        );
    }

    #[test]
    fn test_ground_vector_and_high_resolution_position() {
        let vector = ground_vector(&[0x80 | 0x07, 0xd0, 0x40, 0x00]).unwrap();
        assert!(vector.range_exceeded);
        assert_eq!(vector.ground_speed, 2000);
        assert_eq!(vector.track_angle_deg(), 90.0);
        let position = high_resolution_position(&[0x40, 0, 0, 0, 0xc0, 0, 0, 0]).unwrap();
        assert_eq!(position.latitude_deg(), 180.0);
        assert_eq!(position.longitude_deg(), -180.0);
    }
}
