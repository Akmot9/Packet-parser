// Copyright (c) 2025 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use internet::InternetPacket;

use crate::{errors::ParsedPacketError, DataLink};

pub mod application;
pub mod data_link;
pub mod internet;
// You can determine either a full raw packet that will return a PacketParsed struct composed of data link network transportand application layers.
// Or if you need to, you can put your payload in a determine application try from. detemines function are not dependants.

pub struct ParsedPacketPath<'a> {
    pub data_link: DataLink<'a>,
    pub internet: Option<InternetPacket<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for ParsedPacketPath<'a> {
    type Error = ParsedPacketError;

    /// Tente d'analyser un tableau d'octets en un paquet réseau structuré.
    ///
    /// # Étapes d'analyse
    /// 1. Valider la longueur minimale requise pour les paquets.
    /// 2. Décoder la couche lien de données (obligatoire).
    /// 3. Les couches réseau, transport et application sont analysées si nécessaire.
    ///
    /// # Erreurs
    /// - [`ParsedPacketError::InvalidLength`] si le paquet est trop court.
    /// - Erreurs spécifiques pour chaque couche si les données ne respectent pas les formats attendus.
    fn try_from(packets: &'a [u8]) -> Result<Self, Self::Error> {
        // Étape 1 : Valider la longueur minimale du paquet.

        // Étape 2 : Analyser la couche lien de données.
        let data_link = DataLink::try_from(packets)?;
        let internet: Option<InternetPacket<'a>> =
            Some(InternetPacket::try_from(data_link.payload)?);
        // Les couches réseau, transport et application ne sont pas encore implémentées.
        Ok(ParsedPacketPath {
            data_link,
            internet,
            // _transport: None,
            // _application: None,
        })
    }
}
