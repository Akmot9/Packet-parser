// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Le moteur : le pipeline L3/L4/L7 que traversent [`parse`](super::parse),
//! [`parse_with`](super::parse_with) et [`parse_timed`](super::parse_timed),
//! une etape par couche, puis la detection de tunnel.

use super::application::Application;
use super::data_link::stp::BpduPacket;
use super::internet::Internet;
use super::transport::Transport;
use super::{
    CorruptedLayer, CorruptedLayerKind, DecodeAsProtocol, PacketFlow, dispatch, link, tunnel,
};
use crate::{
    LinkLayer, NetworkProtocol, ParseError,
    errors::{internet::InternetError, transport::TransportError},
    timing::{NoTiming, Stage, TimingSink},
};

impl<'a> PacketFlow<'a> {
    fn parse_application_from_transport(
        transport: &Transport<'a>,
        decode_as: &[(u16, DecodeAsProtocol)],
    ) -> Option<Application> {
        // Toute la politique de classification L7 — gardes de transport,
        // gardes de port, priorites, memoisation des sondes — vit dans la
        // table declarative de `dispatch` (audit 8.1.0 §5.3).
        dispatch::classify(transport, decode_as)
    }

    /// Parses the internet layer from the data-link layer, dispatching on the
    /// EtherType. An unknown EtherType yields `(None, None)`; a known
    /// EtherType with a corrupt payload yields `(None, Some(corruption))` —
    /// never a hard error, so the data-link information is preserved.
    #[inline(always)]
    fn parse_l3(
        network_protocol: NetworkProtocol,
        network_payload: &'a [u8],
    ) -> (Option<Internet<'a>>, Option<CorruptedLayer>) {
        match Internet::try_from_network_parts(network_protocol, network_payload) {
            Ok(internet) => (Some(internet), None),
            Err(InternetError::UnsupportedProtocol) => (None, None),
            Err(e) => (
                None,
                Some(CorruptedLayer {
                    layer: CorruptedLayerKind::Internet,
                    error: e.to_string(),
                }),
            ),
        }
    }

    #[inline(always)]
    fn parse_l4(
        internet: Option<&Internet<'a>>,
    ) -> (Option<Transport<'a>>, Option<CorruptedLayer>) {
        match internet {
            Some(internet) => {
                match Transport::try_from_parts(internet.payload_protocol, internet.payload) {
                    Ok(transport) => (Some(transport), None),
                    Err(TransportError::UnsupportedProtocol) => (None, None),
                    Err(e) => (
                        None,
                        Some(CorruptedLayer {
                            layer: CorruptedLayerKind::Transport,
                            error: e.to_string(),
                        }),
                    ),
                }
            }
            None => (None, None),
        }
    }

    /// Anomalie semantique TCP (SYN+FIN, bits reserves) : **conserver et
    /// signaler** (#24). La couche transport reste — donc ses ports, et la
    /// correlation de flux — l'anomalie est rapportee dans `corrupted`, et la
    /// couche application n'est pas sondee : ce payload ne vient pas d'une
    /// pile conforme.
    ///
    /// Fonction froide, hors du pipeline commun : tisser ce cas dans
    /// `parse_l4` et dans l'etape L7 coutait ~10 ns a CHAQUE segment TCP
    /// (mesure sur le paquet de reference), pour un cas qui ne se presente
    /// presque jamais. Le chemin chaud n'en garde qu'un branchement.
    #[cold]
    #[inline(never)]
    fn anomalous_tcp_flow(
        data_link: LinkLayer<'a>,
        internet: Option<Internet<'a>>,
        transport: Transport<'a>,
        l3_corruption: Option<CorruptedLayer>,
    ) -> Self {
        let anomaly = match &transport.details {
            Some(crate::TransportDetails::Tcp(tcp)) => tcp.anomaly(),
            _ => None,
        };
        let l4_corruption = anomaly.map(|anomaly| CorruptedLayer {
            layer: CorruptedLayerKind::Transport,
            error: TransportError::from(anomaly).to_string(),
        });
        PacketFlow {
            data_link,
            internet,
            transport: Some(transport),
            application: None,
            inner: None,
            corrupted: l3_corruption.or(l4_corruption),
        }
    }

    /// If the transport layer encapsulates a tunnel (e.g. CAPWAP), record the
    /// tunnel name as THIS flow's application protocol and parse the inner
    /// packet into `inner`. Otherwise, best-effort application detection.
    #[inline(always)]
    fn parse_l7_and_inner(
        internet: Option<&Internet<'a>>,
        transport: Option<&Transport<'a>>,
        depth: u8,
        decode_as: &[(u16, DecodeAsProtocol)],
    ) -> (Option<Application>, Option<Box<PacketFlow<'a>>>) {
        // Tunnels au niveau IP d'abord (GRE, IP-in-IP) : leur detection ne
        // depend pas de la couche transport — GRE n'en a pas, et elle ne
        // doit pas reposer sur le Transport creux du fourre-tout L4.
        if let Some(internet) = internet
            && let Some((tunnel_name, inner_flow)) =
                tunnel::detect_inner_l3(internet, depth, decode_as)
        {
            return (
                Some(Application {
                    application_protocol: tunnel_name,
                }),
                Some(Box::new(inner_flow)),
            );
        }

        match transport {
            Some(transport) => match tunnel::detect_inner(transport, depth, decode_as) {
                Some((tunnel_name, inner_flow)) => (
                    Some(Application {
                        application_protocol: tunnel_name,
                    }),
                    Some(Box::new(inner_flow)),
                ),
                None => (
                    Self::parse_application_from_transport(transport, decode_as),
                    None,
                ),
            },
            None => (None, None),
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
            application_protocol: "STP",
        })
    }

    /// Parses the shared L3/L4/L7 pipeline from a normalized link decoder
    /// output. `depth` bounds tunnel nesting.
    pub(crate) fn parse_decoded(
        decoded: link::DecodedLink<'a>,
        depth: u8,
    ) -> Result<Self, ParseError> {
        Self::parse_decoded_with(decoded, depth, &[])
    }

    /// Variante avec les ports declares par l'appelant (« Decode As »),
    /// propages jusqu'au dispatch applicatif, y compris dans les tunnels.
    pub(crate) fn parse_decoded_with(
        decoded: link::DecodedLink<'a>,
        depth: u8,
        decode_as: &[(u16, DecodeAsProtocol)],
    ) -> Result<Self, ParseError> {
        Self::parse_decoded_into(decoded, depth, decode_as, &mut NoTiming)
    }

    /// Le pipeline L3/L4/L7, unique : le chemin normal le traverse avec
    /// [`NoTiming`] (chaque etape se reduit a son corps), [`parse_timed`]
    /// avec un [`ParseTiming`](crate::timing::ParseTiming). `l7` inclut la
    /// detection de tunnel et le parsing recursif des paquets encapsules,
    /// qui eux ne sont pas chronometres separement.
    #[inline(always)]
    pub(crate) fn parse_decoded_into(
        decoded: link::DecodedLink<'a>,
        depth: u8,
        decode_as: &[(u16, DecodeAsProtocol)],
        sink: &mut impl TimingSink,
    ) -> Result<Self, ParseError> {
        let (data_link, network_protocol, network_payload) = decoded.into_parts();
        let (internet, l3_corruption) = sink.time(Stage::L3, || {
            Self::parse_l3(network_protocol, network_payload)
        });
        let (transport, l4_corruption) = sink.time(Stage::L4, || Self::parse_l4(internet.as_ref()));
        let transport = match transport {
            Some(transport) if transport.is_anomalous_tcp() => {
                return Ok(Self::anomalous_tcp_flow(
                    data_link,
                    internet,
                    transport,
                    l3_corruption,
                ));
            }
            transport => transport,
        };
        let (application, inner) = sink.time(Stage::L7, || {
            let (application, inner) =
                Self::parse_l7_and_inner(internet.as_ref(), transport.as_ref(), depth, decode_as);
            (application.or_else(|| Self::detect_stp(&data_link)), inner)
        });

        Ok(PacketFlow {
            data_link,
            internet,
            transport,
            application,
            inner,
            corrupted: l3_corruption.or(l4_corruption),
        })
    }
}
