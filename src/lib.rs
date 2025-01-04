//! # Packet Parser Crate
//!
//! Bienvenue dans **Packet Parser**, une crate modulaire et extensible pour analyser des paquets réseau bruts.
//! Ce projet décompose chaque paquet en plusieurs couches (lien de données, réseau, transport, application), 
//! facilitant leur compréhension et leur manipulation dans un environnement Rust moderne.
//!
//! ## Pourquoi cette crate existe-t-elle ?
//!
//! Lorsque vous interceptez des paquets réseau bruts, ils apparaissent comme un simple tableau d'octets.
//! Pour extraire des informations utiles (adresses MAC, IP, ports, etc.), il faut les interpréter en respectant
//! les protocoles réseau. Cette crate automatise ce processus et le rend accessible via une interface propre et modulaire.
//!
//! ## Comment cela fonctionne-t-il ?
//!
//! L'analyse d'un paquet suit une logique **du plus bas niveau au plus haut niveau** :
//! 1. **Lien de données (Data Link)** : Identifie la structure de base, comme les adresses MAC et le type de protocole.
//! 2. **Réseau (Network)** : Analyse les protocoles comme IPv4 ou IPv6 pour extraire des informations d'adressage.
//! 3. **Transport (Transport)** : Identifie les protocoles comme TCP ou UDP et leurs ports.
//! 4. **Application (Application)** : Tente d'interpréter les données applicatives (DNS, HTTP, etc.).
//!
//! ## Modules
//!
//! Voici les modules principaux qui forment la base de cette crate :
//!
//! - [`displays`] : Offre des outils pour afficher les paquets de manière lisible (par exemple, en tant que texte ou JSON).
//! - [`errors`] : Contient des erreurs spécifiques à chaque étape de l'analyse.
//! - [`parsed_packet`] : Fournit les structures et fonctions pour décoder les différentes couches des paquets réseau.
//! - [`valildations`] : Vérifie l'intégrité des données avant de les interpréter.
//!
//! ## Exemple d'utilisation
//!
//! Analysons un paquet brut en Rust :
//!
//! ```rust
//! use packet_parser::ParsedPacket;
//! use std::convert::TryFrom;
//!
//! fn main() {
//!     let raw_data: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* autres octets */];
//!     match ParsedPacket::try_from(raw_data) {
//!         Ok(packet) => println!("Paquet analysé avec succès : {:?}", packet),
//!         Err(e) => eprintln!("Erreur lors de l'analyse : {:?}", e),
//!     }
//! }
//! ```
//!
//! ## Comment contribuer ?
//!
//! Ce projet est conçu pour évoluer avec le temps. Les contributions sont bienvenues, que ce soit pour :
//! - Ajouter de nouveaux protocoles réseau.
//! - Améliorer les validations existantes.
//! - Documenter les fonctionnalités de manière encore plus accessible.

pub mod displays;
pub mod errors;
pub mod parsed_packet;
pub mod valildations;

use core::net;
use std::convert::TryFrom;

use parsed_packet::{
    application::Application, data_link::DataLink, network::Network, transport::Transport,
};

use crate::{errors::ParsedPacketError, valildations::validate_packet_length};

/// Représente un paquet réseau analysé.
///
/// Chaque couche est représentée par une structure distincte.
/// Les couches supérieures sont optionnelles pour permettre de gérer des paquets
/// incomplets ou partiels, ce qui est courant lors de la capture en temps réel.
///
/// ### Exemple d'utilisation
/// ```rust
/// use packet_parser::ParsedPacket;
/// use std::convert::TryFrom;
///
/// let raw_data: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// match ParsedPacket::try_from(raw_data) {
///     Ok(packet) => println!("Paquet analysé : {:?}", packet),
///     Err(e) => eprintln!("Erreur : {:?}", e),
/// }
/// ```
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    /// Données de la couche lien de données (par exemple, adresses MAC, EtherType).
    data_link: DataLink<'a>,

    /// Données de la couche réseau (par exemple, IPv4, IPv6).
    network: Option<Network<'a>>,

    /// Données de la couche transport (par exemple, TCP, UDP).
    _transport: Option<Transport<'a>>,

    /// Données de la couche application (par exemple, HTTP, DNS).
    _application: Option<Application>,

    /// Taille totale du paquet en octets.
    pub size: usize,
}

impl<'a> TryFrom<&'a [u8]> for ParsedPacket<'a> {
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
        validate_packet_length(packets)?;

        // Étape 2 : Analyser la couche lien de données.
        let data_link = DataLink::try_from(packets)?;
        let network = Some(Network::try_from(data_link.payload)?);
        // Les couches réseau, transport et application ne sont pas encore implémentées.
        Ok(ParsedPacket {
            data_link,
            network,
            _transport: None,
            _application: None,
            size: packets.len(),
        })
    }
}
