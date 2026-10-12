// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 063 — Sensor Status Messages (EUROCONTROL-SPEC-0149-10) : l'etat de
//! chaque capteur vu du SDPS (connexion, NOGO par technologie, biais de
//! temps, de distance et d'azimut), en accompagnement des pistes CAT 062.

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, TimeOfDay},
};

/// Etat de la connexion du capteur (I063/060, CON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConnectionStatus {
    Operational,
    Degraded,
    Initialization,
    NotConnected,
}

/// Premier octet de I063/060, Sensor Configuration and Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SensorConfiguration {
    pub connection: ConnectionStatus,
    pub psr_nogo: bool,
    pub ssr_nogo: bool,
    pub mode_s_nogo: bool,
    pub ads_nogo: bool,
    pub mlt_nogo: bool,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Gain et biais en distance (I063/080, I063/090).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RangeGainAndBias {
    /// Gain, LSB 10^-5.
    pub gain: i16,
    /// Biais, LSB 1/128 NM.
    pub bias: i16,
}

impl RangeGainAndBias {
    pub fn bias_nm(self) -> f64 {
        f64::from(self.bias) / 128.0
    }
}

/// Les items decodes d'un record CAT 063.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SensorStatus {
    pub data_source: Option<DataSourceIdentifier>,
    /// I063/015.
    pub service_identification: Option<u8>,
    /// I063/030.
    pub time_of_message: Option<TimeOfDay>,
    /// I063/050, le capteur dont il est question.
    pub sensor: Option<DataSourceIdentifier>,
    pub configuration: Option<SensorConfiguration>,
    /// I063/070, en millisecondes.
    pub time_stamping_bias_ms: Option<i16>,
    /// I063/080.
    pub ssr_mode_s_range: Option<RangeGainAndBias>,
    /// I063/081, LSB 360/2^16 degres.
    pub ssr_mode_s_azimuth_bias: Option<i16>,
    /// I063/090.
    pub psr_range: Option<RangeGainAndBias>,
    /// I063/091, LSB 360/2^16 degres.
    pub psr_azimuth_bias: Option<i16>,
    /// I063/092, LSB 360/2^16 degres.
    pub psr_elevation_bias: Option<i16>,
}

impl SensorStatus {
    /// Decode les items typees d'un record CAT 063 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 63 {
            return None;
        }
        let i16_item = |id: &str| {
            record.item(id).and_then(|d| match d {
                [high, low] => Some(i16::from_be_bytes([*high, *low])),
                _ => None,
            })
        };
        Some(Self {
            data_source: record
                .item("I063/010")
                .and_then(DataSourceIdentifier::from_item),
            service_identification: record.item("I063/015").and_then(|d| d.first().copied()),
            time_of_message: record.item("I063/030").and_then(TimeOfDay::from_item),
            sensor: record
                .item("I063/050")
                .and_then(DataSourceIdentifier::from_item),
            configuration: record.item("I063/060").and_then(configuration),
            time_stamping_bias_ms: i16_item("I063/070"),
            ssr_mode_s_range: record.item("I063/080").and_then(gain_and_bias),
            ssr_mode_s_azimuth_bias: i16_item("I063/081"),
            psr_range: record.item("I063/090").and_then(gain_and_bias),
            psr_azimuth_bias: i16_item("I063/091"),
            psr_elevation_bias: i16_item("I063/092"),
        })
    }
}

fn configuration(data: &[u8]) -> Option<SensorConfiguration> {
    let first = *data.first()?;
    Some(SensorConfiguration {
        connection: match first >> 6 {
            0 => ConnectionStatus::Operational,
            1 => ConnectionStatus::Degraded,
            2 => ConnectionStatus::Initialization,
            _ => ConnectionStatus::NotConnected,
        },
        psr_nogo: first & 0x20 != 0,
        ssr_nogo: first & 0x10 != 0,
        mode_s_nogo: first & 0x08 != 0,
        ads_nogo: first & 0x04 != 0,
        mlt_nogo: first & 0x02 != 0,
        raw: first,
    })
}

fn gain_and_bias(data: &[u8]) -> Option<RangeGainAndBias> {
    match data {
        [g0, g1, b0, b1] => Some(RangeGainAndBias {
            gain: i16::from_be_bytes([*g0, *g1]),
            bias: i16::from_be_bytes([*b0, *b1]),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// Trame 1105 de pcaps_exemple/protocols/asterix/wireshark_8579_radardata.pcap
    /// (224.3.2.1:30202) : un capteur SAC 34 / SIC 26 operationnel mais NOGO
    /// sur toutes ses technologies, biais de temps 75 ms, recoupe avec
    /// tshark 4.6.6.
    const RADARDATA_FRAME_1105: &str = "3f000ffc93640259de69221a3e004b";

    #[test]
    fn test_decodes_a_real_sensor_status_against_tshark() {
        let bytes = hex::decode(RADARDATA_FRAME_1105).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 1105");
        let status = SensorStatus::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(status.data_source.map(|d| (d.sac, d.sic)), Some((147, 100)));
        assert_eq!(status.service_identification, Some(2));
        assert_eq!(
            status.time_of_message.map(TimeOfDay::seconds),
            Some(46_012.820_312_5)
        );
        assert_eq!(status.sensor.map(|d| (d.sac, d.sic)), Some((34, 26)));
        let configuration = status.configuration.unwrap();
        assert_eq!(configuration.connection, ConnectionStatus::Operational);
        assert!(configuration.psr_nogo && configuration.ssr_nogo && configuration.mode_s_nogo);
        assert!(configuration.ads_nogo && configuration.mlt_nogo);
        assert_eq!(configuration.raw, 0x3e);
        assert_eq!(status.time_stamping_bias_ms, Some(75));
        assert_eq!(status.ssr_mode_s_range, None);
        assert_eq!(status.psr_azimuth_bias, None);
    }

    /// Octets synthetiques : biais SSR et PSR (FSPEC `03 f0` : FRN 7 a 11).
    #[test]
    fn test_decodes_gains_and_biases() {
        let bytes = [
            0x3f, 0x00, 0x13, 0x03, 0xf0, 0x00, 0x64, 0xff, 0x80, 0xff, 0xff, 0x27, 0x10, 0x00,
            0x40, 0x80, 0x00, 0x00, 0x10,
        ];
        let packet = AsterixPacket::try_from(&bytes[..]).expect("synthetique");
        let status = SensorStatus::from_record(&packet.blocks[0].records[0]).unwrap();
        let ssr = status.ssr_mode_s_range.unwrap();
        assert_eq!((ssr.gain, ssr.bias), (100, -128));
        assert_eq!(ssr.bias_nm(), -1.0);
        assert_eq!(status.ssr_mode_s_azimuth_bias, Some(-1));
        let psr = status.psr_range.unwrap();
        assert_eq!((psr.gain, psr.bias), (10_000, 64));
        assert_eq!(psr.bias_nm(), 0.5);
        assert_eq!(status.psr_azimuth_bias, Some(-32_768));
        assert_eq!(status.psr_elevation_bias, Some(16));
        assert_eq!(status.configuration, None);
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            SensorStatus::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
