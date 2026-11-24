// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Le moteur : le pipeline L3/L4/L7 que traversent [`parse`](super::parse),
//! [`parse_with`](super::parse_with) et [`parse_timed`](super::parse_timed),
//! une etape par couche, puis la detection de tunnel.

use super::application::Application;
use super::application::custom;
use super::data_link::stp::BpduPacket;
use super::internet::Internet;
use super::transport::Transport;
use super::{CorruptedLayer, DEFAULT_CONFIG, PacketFlow, ParseConfig, dispatch, link, tunnel};
use crate::parse::application::protocol::ApplicationProtocol;
use crate::{
    LinkLayer, NetworkProtocol, ParseError,
    errors::{internet::InternetError, transport::TransportError},
    timing::{NoTiming, Stage, TimingSink},
};

impl<'a> PacketFlow<'a> {
    fn parse_application_from_transport(
        transport: &Transport<'a>,
        config: &ParseConfig,
    ) -> Option<Application> {
        // Toute la politique de classification L7 — gardes de transport,
        // gardes de port, priorites, memoisation des sondes — vit dans la
        // table declarative de `dispatch` (audit 8.1.0 §5.3).
        let application = dispatch::classify(transport, &config.decode_as);
        // Les parseurs ajoutes par l'appelant (#319) ne passent qu'apres la
        // table, sur ce qu'elle a laisse `Unknown` : ils ne prennent jamais
        // un payload a la crate. Sans parseur, un seul test de longueur.
        match application {
            Some(Application {
                protocol: ApplicationProtocol::Unknown,
            }) if !config.parsers.is_empty() => custom::classify(&config.parsers, transport)
                .map(|protocol| Application { protocol })
                .or(application),
            application => application,
        }
    }

    /// Le flux d'une trame dont seule la couche liaison est lue : le point
    /// de depart que [`fill_layers_into`](Self::fill_layers_into) complete
    /// sur place.
    #[inline(always)]
    fn from_link(data_link: LinkLayer<'a>) -> Self {
        PacketFlow {
            data_link,
            internet: None,
            transport: None,
            application: None,
            inner: None,
            corrupted: None,
        }
    }

    /// Parses the internet layer from the data-link layer, dispatching on the
    /// EtherType. An unknown EtherType leaves `internet` and `corrupted`
    /// empty; a known EtherType with a corrupt payload is reported in
    /// `corrupted` — never a hard error, so the data-link information is
    /// preserved.
    #[inline(always)]
    fn fill_l3(&mut self, network_protocol: NetworkProtocol, network_payload: &'a [u8]) {
        match Internet::try_from_network_parts(network_protocol, network_payload) {
            Ok(internet) => self.internet = Some(internet),
            Err(InternetError::UnsupportedProtocol) => {}
            Err(e) => self.corrupted = Some(CorruptedLayer::from(e)),
        }
    }

    /// La couche transport, lue dans la charge de la couche internet. Sans
    /// couche internet il n'y a rien a lire, et `corrupted` garde ce que
    /// l'etape L3 y a mis : les deux etapes ne signalent jamais ensemble.
    #[inline(always)]
    fn fill_l4(&mut self) {
        let Some(internet) = &self.internet else {
            return;
        };
        match Transport::try_from_parts(internet.payload_protocol, internet.payload) {
            Ok(transport) => self.transport = Some(transport),
            Err(TransportError::UnsupportedProtocol) => {}
            Err(e) => self.corrupted = Some(CorruptedLayer::from(e)),
        }
    }

    /// Anomalie semantique TCP (SYN+FIN, bits reserves) : **conserver et
    /// signaler** (#24). La couche transport reste — donc ses ports, et la
    /// correlation de flux — l'anomalie est rapportee dans `corrupted`, et la
    /// couche application n'est pas sondee : ce payload ne vient pas d'une
    /// pile conforme.
    ///
    /// Fonction froide, hors du pipeline commun : tisser ce cas dans
    /// `fill_l4` et dans l'etape L7 coutait ~10 ns a CHAQUE segment TCP
    /// (mesure sur le paquet de reference), pour un cas qui ne se presente
    /// presque jamais. Le chemin chaud n'en garde qu'un branchement.
    #[cold]
    #[inline(never)]
    fn report_tcp_anomaly(&mut self) {
        let anomaly = match &self.transport {
            Some(Transport {
                details: Some(crate::TransportDetails::Tcp(tcp)),
                ..
            }) => tcp.anomaly(),
            _ => None,
        };
        let l4_corruption =
            anomaly.map(|anomaly| CorruptedLayer::from(TransportError::from(anomaly)));
        self.corrupted = self.corrupted.take().or(l4_corruption);
    }

    /// If the transport layer encapsulates a tunnel (e.g. CAPWAP), record the
    /// tunnel name as THIS flow's application protocol and parse the inner
    /// packet into `inner`. Otherwise, best-effort application detection.
    #[inline(always)]
    fn fill_l7_and_inner(&mut self, depth: u8, config: &ParseConfig) {
        // Tunnels au niveau IP d'abord (GRE, IP-in-IP) : leur detection ne
        // depend pas de la couche transport — GRE n'en a pas, et elle ne
        // doit pas reposer sur le Transport creux du fourre-tout L4.
        if let Some(internet) = &self.internet
            && let Some((tunnel_name, inner_flow)) =
                tunnel::detect_inner_l3(internet, depth, config)
        {
            self.application = Some(Application {
                protocol: tunnel_name,
            });
            self.inner = Some(Box::new(inner_flow));
            return;
        }

        if let Some(transport) = &self.transport {
            let (application, inner) = Self::application_and_inner(transport, depth, config);
            self.application = application;
            self.inner = inner;
        }
        if self.application.is_none() {
            self.application = Self::detect_stp(&self.data_link);
        }
    }

    /// L'etape L7 d'un flux qui a une couche transport : un tunnel porte par
    /// le transport donne son nom au flux externe et son paquet interne a
    /// `inner` ; sinon la table de dispatch tranche. Chemin unique de
    /// `parse` et de [`classify_payload`](super::classify_payload) : pour
    /// un flux externe (`depth` nul), les deux rendent la meme etiquette
    /// par construction, tunnels compris (#219). `classify_payload` n'a pas
    /// de profondeur : au dernier niveau que `parse` garde, ou il ne
    /// cherche plus de tunnel, elle le nomme encore.
    #[inline(always)]
    pub(super) fn application_and_inner(
        transport: &Transport<'a>,
        depth: u8,
        config: &ParseConfig,
    ) -> (Option<Application>, Option<Box<PacketFlow<'a>>>) {
        match tunnel::detect_inner(transport, depth, config) {
            Some((tunnel_name, inner_flow)) => (
                Some(Application {
                    protocol: tunnel_name,
                }),
                Some(Box::new(inner_flow)),
            ),
            None => (
                Self::parse_application_from_transport(transport, config),
                None,
            ),
        }
    }

    /// Etiquette les BPDU Spanning Tree (STP/RSTP/MSTP, issue #4) : trame
    /// 802.3 (champ longueur, pas un EtherType) vers 01:80:c2:00:00:00, LLC
    /// 42-42-03, BPDU valide. STP vit sous la couche reseau : sans ce
    /// controle, la trame ressortait avec L3/L4/L7 a None et aucun signal.
    fn detect_stp(link: &LinkLayer<'_>) -> Option<Application> {
        use crate::checks::data_link::stp::{
            BRIDGE_GROUP_ADDRESS, LLC_STP_HEADER, MAX_IEEE_802_3_LENGTH,
        };

        let frame = link.as_ethernet()?;
        if frame.destination_mac.0 != BRIDGE_GROUP_ADDRESS
            || frame.ethertype.0 > MAX_IEEE_802_3_LENGTH
        {
            return None;
        }
        // Le champ longueur 802.3 delimite LLC + BPDU ; le bourrage Ethernet
        // eventuel reste au-dela et n'est pas soumis au parseur.
        let llc = frame.payload.get(..usize::from(frame.ethertype.0))?;
        let bpdu = llc.strip_prefix(&LLC_STP_HEADER)?;
        BpduPacket::try_from(bpdu).ok().map(|_| Application {
            protocol: ApplicationProtocol::Stp,
        })
    }

    /// Parses the shared L3/L4/L7 pipeline from a normalized link decoder
    /// output. `depth` bounds tunnel nesting.
    #[inline(always)]
    pub(crate) fn parse_decoded(
        decoded: link::DecodedLink<'a>,
        depth: u8,
    ) -> Result<Self, ParseError> {
        Self::parse_decoded_with(decoded, depth, &DEFAULT_CONFIG)
    }

    /// Variante avec la configuration de l'appelant : ports declares
    /// (« Decode As ») et parseurs ajoutes (#319), propages jusqu'au dispatch
    /// applicatif, y compris dans les tunnels.
    #[inline(always)]
    pub(crate) fn parse_decoded_with(
        decoded: link::DecodedLink<'a>,
        depth: u8,
        config: &ParseConfig,
    ) -> Result<Self, ParseError> {
        let (data_link, network_protocol, network_payload) = decoded.into_parts();
        let mut flow = Self::from_link(data_link);
        flow.fill_layers(network_protocol, network_payload, depth, config);
        Ok(flow)
    }

    /// Le pipeline du chemin normal, hors ligne et sans mesure : une seule
    /// instance, que `parse`, `parse_with` et les tunnels appellent sur le
    /// flux qu'ils viennent de creer.
    #[inline(never)]
    fn fill_layers(
        &mut self,
        network_protocol: NetworkProtocol,
        network_payload: &'a [u8],
        depth: u8,
        config: &ParseConfig,
    ) {
        self.fill_layers_into(
            network_protocol,
            network_payload,
            depth,
            config,
            &mut NoTiming,
        );
    }

    /// Le pipeline chronometre de [`parse_timed`](super::parse_timed).
    #[inline(always)]
    pub(crate) fn parse_decoded_into(
        decoded: link::DecodedLink<'a>,
        depth: u8,
        config: &ParseConfig,
        sink: &mut impl TimingSink,
    ) -> Result<Self, ParseError> {
        let (data_link, network_protocol, network_payload) = decoded.into_parts();
        let mut flow = Self::from_link(data_link);
        flow.fill_layers_into(network_protocol, network_payload, depth, config, sink);
        Ok(flow)
    }

    /// Le pipeline L3/L4/L7, unique : le chemin normal le traverse avec
    /// [`NoTiming`] (chaque etape se reduit a son corps), [`parse_timed`](super::parse_timed)
    /// avec un [`ParseTiming`](crate::timing::ParseTiming). `l7` inclut la
    /// detection de tunnel et le parsing recursif des paquets encapsules,
    /// qui eux ne sont pas chronometres separement.
    ///
    /// Chaque etape ecrit sa couche a sa place dans le flux. Rendues par
    /// valeur d'une etape a l'autre, la couche internet (208 octets) etait
    /// recopiee trois fois et la couche transport deux (mesure sur un
    /// segment TCP sans charge).
    #[inline(always)]
    fn fill_layers_into(
        &mut self,
        network_protocol: NetworkProtocol,
        network_payload: &'a [u8],
        depth: u8,
        config: &ParseConfig,
        sink: &mut impl TimingSink,
    ) {
        sink.time(Stage::L3, || {
            self.fill_l3(network_protocol, network_payload);
        });
        sink.time(Stage::L4, || self.fill_l4());
        if let Some(transport) = &self.transport
            && transport.is_anomalous_tcp()
        {
            self.report_tcp_anomaly();
            return;
        }
        sink.time(Stage::L7, || self.fill_l7_and_inner(depth, config));
    }
}
