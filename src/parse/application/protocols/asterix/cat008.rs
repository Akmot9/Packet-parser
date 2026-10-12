// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! CAT 008 — Monoradar Derived Weather Information (EUROCONTROL-SPEC-0149-3) :
//! les images meteo d'un radar primaire, en vecteurs polaires ou cartesiens
//! et en contours, encadrees par des messages de debut et de fin d'image.
//! Les vecteurs eux-memes restent accessibles en octets via
//! [`AsterixRecord::item`] ; seuls leur nombre et les items d'enveloppe
//! sont decodes en valeurs typees.

use super::{
    AsterixRecord,
    fields::{DataSourceIdentifier, TimeOfDay},
};

/// Type de message (I008/000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MessageType {
    PolarVector,
    CartesianVectorStartLength,
    ContourRecord,
    CartesianVectorStartEnd,
    StartOfPicture,
    EndOfPicture,
    Other(u8),
}

impl From<u8> for MessageType {
    fn from(code: u8) -> Self {
        match code {
            1 => Self::PolarVector,
            2 => Self::CartesianVectorStartLength,
            3 => Self::ContourRecord,
            4 => Self::CartesianVectorStartEnd,
            254 => Self::StartOfPicture,
            255 => Self::EndOfPicture,
            other => Self::Other(other),
        }
    }
}

/// Premier octet de I008/020, Vector Qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VectorQualifier {
    /// ORG = 1 : coordonnees systeme (sinon locales).
    pub system_coordinates: bool,
    /// Niveau d'intensite, trois bits.
    pub intensity: u8,
    /// Orientation du hachurage, trois bits.
    pub shading: u8,
    /// Le premier octet, tel quel (FX compris).
    pub raw: u8,
}

/// Identifiant de contour (I008/040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ContourIdentifier {
    pub system_coordinates: bool,
    pub intensity: u8,
    /// FST/LST, deux bits : 0 intermediaire, 1 dernier, 2 premier, 3 seul.
    pub position: u8,
    /// Numero de serie du contour.
    pub serial_number: u8,
}

/// Etat du traitement (I008/100).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ProcessingStatus {
    /// F, cinq bits signes : facteur d'echelle.
    pub scaling_factor: i8,
    /// R, trois bits : etage de reduction en cours.
    pub reduction_stage: u8,
    /// Q, quinze bits : parametres de traitement.
    pub parameters: u16,
}

/// Les items decodes d'un record CAT 008.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WeatherMessage {
    pub data_source: Option<DataSourceIdentifier>,
    pub message_type: Option<MessageType>,
    pub vector_qualifier: Option<VectorQualifier>,
    /// Nombre de vecteurs polaires (I008/036).
    pub polar_vector_count: Option<u8>,
    /// Nombre de vecteurs cartesiens point de depart + longueur (I008/034).
    pub cartesian_vector_count: Option<u8>,
    /// Nombre de vecteurs cartesiens point de depart + point d'arrivee
    /// (I008/038).
    pub cartesian_start_end_vector_count: Option<u8>,
    pub contour_identifier: Option<ContourIdentifier>,
    /// Nombre de points de contour (I008/050).
    pub contour_point_count: Option<u8>,
    /// I008/090.
    pub time_of_day: Option<TimeOfDay>,
    pub processing_status: Option<ProcessingStatus>,
    /// Premier octet de I008/110, Station Configuration Status.
    pub station_configuration: Option<u8>,
    /// I008/120, nombre total d'items de l'image.
    pub total_items: Option<u16>,
}

impl WeatherMessage {
    /// Decode les items typees d'un record CAT 008 ; `None` si le record est
    /// d'une autre categorie.
    pub fn from_record(record: &AsterixRecord<'_>) -> Option<Self> {
        if record.category != 8 {
            return None;
        }
        let rep = |id: &str| record.item(id).and_then(|d| d.first().copied());
        Some(Self {
            data_source: record
                .item("I008/010")
                .and_then(DataSourceIdentifier::from_item),
            message_type: record
                .item("I008/000")
                .and_then(|d| d.first().map(|code| MessageType::from(*code))),
            vector_qualifier: record.item("I008/020").and_then(vector_qualifier),
            polar_vector_count: rep("I008/036"),
            cartesian_vector_count: rep("I008/034"),
            cartesian_start_end_vector_count: rep("I008/038"),
            contour_identifier: record.item("I008/040").and_then(contour_identifier),
            contour_point_count: rep("I008/050"),
            time_of_day: record.item("I008/090").and_then(TimeOfDay::from_item),
            processing_status: record.item("I008/100").and_then(processing_status),
            station_configuration: rep("I008/110"),
            total_items: record.item("I008/120").and_then(|d| match d {
                [high, low] => Some(u16::from_be_bytes([*high, *low])),
                _ => None,
            }),
        })
    }
}

fn vector_qualifier(data: &[u8]) -> Option<VectorQualifier> {
    let first = *data.first()?;
    Some(VectorQualifier {
        system_coordinates: first & 0x80 != 0,
        intensity: (first >> 4) & 0x07,
        shading: (first >> 1) & 0x07,
        raw: first,
    })
}

fn contour_identifier(data: &[u8]) -> Option<ContourIdentifier> {
    match data {
        [first, serial] => Some(ContourIdentifier {
            system_coordinates: first & 0x80 != 0,
            intensity: (first >> 4) & 0x07,
            position: (first >> 2) & 0x03,
            serial_number: *serial,
        }),
        _ => None,
    }
}

fn processing_status(data: &[u8]) -> Option<ProcessingStatus> {
    match data {
        [first, high, low] => Some(ProcessingStatus {
            // Cinq bits signes : etendus depuis le bit 5.
            scaling_factor: ((first & 0xf8) as i8) >> 3,
            reduction_stage: first & 0x07,
            parameters: u16::from_be_bytes([*high, *low]) >> 1,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::application::protocols::asterix::AsterixPacket;

    /// Trames 1 et 2 de pcaps_exemple/protocols/asterix/wireshark_9239_cat008only-2.pcap
    /// (239.1.20.1:56520) : debut d'image avec etat du traitement, puis un
    /// message de 73 vecteurs cartesiens, recoupes avec tshark 4.6.6.
    const CAT008ONLY_2_FRAME_1: &str = "08000bc1409319fe300000";
    const CAT008ONLY_2_FRAME_2_HEAD: &str = "0800e4f093190218";

    #[test]
    fn test_decodes_a_real_start_of_picture_against_tshark() {
        let bytes = hex::decode(CAT008ONLY_2_FRAME_1).unwrap();
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 1");
        let message = WeatherMessage::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(message.data_source.map(|d| (d.sac, d.sic)), Some((147, 25)));
        assert_eq!(message.message_type, Some(MessageType::StartOfPicture));
        assert_eq!(
            message.processing_status,
            Some(ProcessingStatus {
                scaling_factor: 6,
                reduction_stage: 0,
                parameters: 0,
            })
        );
        assert_eq!(message.vector_qualifier, None);
        assert_eq!(message.polar_vector_count, None);
        assert_eq!(message.total_items, None);
    }

    #[test]
    fn test_decodes_a_real_vector_message_against_tshark() {
        // En-tete reel de la trame 2, puis 73 vecteurs reels resumes a leurs
        // trois premiers et complete a zero : seul le compte est decode.
        let mut bytes = hex::decode(CAT008ONLY_2_FRAME_2_HEAD).unwrap();
        bytes.push(73);
        bytes.extend_from_slice(&[0x49, 0xef, 0xe5, 0x01, 0xf4, 0xe6, 0x02, 0xf3, 0xe7]);
        bytes.extend(std::iter::repeat_n(0u8, 70 * 3));
        assert_eq!(bytes.len(), 0xe4);
        let packet = AsterixPacket::try_from(bytes.as_slice()).expect("trame 2");
        let message = WeatherMessage::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(
            message.message_type,
            Some(MessageType::CartesianVectorStartLength)
        );
        let qualifier = message.vector_qualifier.unwrap();
        assert!(!qualifier.system_coordinates);
        assert_eq!((qualifier.intensity, qualifier.shading), (1, 4));
        assert_eq!(message.polar_vector_count, Some(73));
        assert_eq!(message.cartesian_vector_count, None);
    }

    /// Octets synthetiques : fin d'image avec identifiant de contour,
    /// points, heure, etat du traitement, configuration et total (FSPEC
    /// `c7 f0`).
    #[test]
    fn test_decodes_contour_and_picture_envelope() {
        let bytes = [
            0x08, 0x00, 0x16, 0xc7, 0xf0, 0x00, 0x01, 0xff, 0x9c, 0x07, 0x01, 0x12, 0x34, 0x38,
            0x41, 0x76, 0xf8, 0x00, 0x02, 0x80, 0x01, 0x02,
        ];
        let packet = AsterixPacket::try_from(&bytes[..]).expect("synthetique");
        let message = WeatherMessage::from_record(&packet.blocks[0].records[0]).unwrap();
        assert_eq!(message.message_type, Some(MessageType::EndOfPicture));
        assert_eq!(
            message.contour_identifier,
            Some(ContourIdentifier {
                system_coordinates: true,
                intensity: 1,
                position: 3,
                serial_number: 7,
            })
        );
        assert_eq!(message.contour_point_count, Some(1));
        assert_eq!(
            message.time_of_day.map(TimeOfDay::seconds),
            Some(28_802.921_875)
        );
        assert_eq!(
            message.processing_status,
            Some(ProcessingStatus {
                scaling_factor: -1,
                reduction_stage: 0,
                parameters: 1,
            })
        );
        assert_eq!(message.station_configuration, Some(0x80));
        assert_eq!(message.total_items, Some(0x0102));
    }

    #[test]
    fn test_rejects_records_of_another_category() {
        let bytes = [0x22, 0x00, 0x06, 0x80, 0x00, 0x01];
        let packet = AsterixPacket::try_from(&bytes[..]).unwrap();
        assert_eq!(
            WeatherMessage::from_record(&packet.blocks[0].records[0]),
            None
        );
    }
}
