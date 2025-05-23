// Copyright (c) 2025 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use application::Application;
use internet::Internet;
use transport::Transport;

use crate::{errors::ParsedPacketError, DataLink};

pub mod application;
pub mod data_link;
pub mod internet;
pub mod transport;
// You can determine either a full raw packet that will return a PacketParsed struct composed of data link network transportand application layers.
// Or if you need to, you can put your payload in a determine application try from. detemines function are not dependants.

pub struct PacketFlux<'a> {
    pub data_link: DataLink<'a>,
    pub internet: Option<Internet<'a>>,
    pub transport: Option<Transport<'a>>,
    pub application: Option<Application<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for PacketFlux<'a> {
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
        // Étape 2 : Analyser la couche lien de données.
        let data_link = DataLink::try_from(packets)?;

        // Étape 3 : Analyser la couche Internet (IP)
        let internet = match Internet::try_from(data_link.payload) {
            Ok(internet) => Some(internet),
            Err(e) => {
                // Log the error or handle it as needed
                eprintln!("Failed to parse Internet layer: {}", e);
                None
            }
        };
        // TODO: si internet est None, on retourne data_link.ethertype
        

        // Étape 4 : Analyser la couche Transport (TCP/UDP)
        let transport = internet.as_ref().and_then(|net| {
            net.payload.and_then(|payload| {
                Transport::try_from(payload)
                    .map_err(|e| {
                        eprintln!("Failed to parse Transport layer: {}", e);
                        e
                    })
                    .ok()
            })
        });
        // TODO: si transport est None, on retourne internet. payload_protocol

        // Étape 5 : Analyser la couche Application si disponible
        let application = transport.as_ref().and_then(|trans| {
            Application::try_from(trans.payload)
                .map_err(|e| {
                    eprintln!("Failed to parse Application layer: {}", e);
                    e
                })
                .ok()
        });

        Ok(PacketFlux {
            data_link,
            internet,
            transport,
            application,
        })
    }
}
