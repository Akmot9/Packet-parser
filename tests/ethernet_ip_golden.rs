// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Golden tests EtherNet/IP sur trames reelles (issue #57), au niveau
//! `PacketFlow` **et** au niveau `EtherNetIpPacket::try_from`.
//!
//! Captures : `pcaps_exemple/protocols/ethernet_ip/` (depot public
//! ITI/ICS-Security-Tools, licence CC-BY-4.0 — voir le `SOURCE.md` du
//! dossier). Les valeurs attendues ont ete figees d'apres le decodage
//! tshark 4.x (`enip`/`cip`) de chaque trame. Le corpus source ne contient
//! aucun RegisterSession (0x65) : la couverture reelle porte sur
//! ListIdentity, SendRRData et SendUnitData.

use packet_parser::parse::application::protocols::ethernet_ip::{
    EtherNetIpCommand, EtherNetIpCommandData, EtherNetIpPacket,
};
use packet_parser::parse::transport::protocols::TransportProtocol;
use packet_parser::{LinkType, parse};

/// `pcaps_exemple/protocols/ethernet_ip/enip_test.pcap`, trame 6 : requete
/// ListIdentity (0x0063) de 10.1.1.167:5262 vers 10.1.1.164:44818 —
/// en-tete d'encapsulation nu (length 0), sender context non nul.
const LIST_IDENTITY_REQUEST_FRAME_HEX: &str = concat!(
    "001907243cca3ca9f42122f808004500004052774000800690f40a0101a70a01",
    "01a4148eaf128c05d66d87b04692501840b07fb000006300000000000000",
    "0000000000000000c1debed100000000"
);

/// `pcaps_exemple/protocols/ethernet_ip/enip_test.pcap`, trame 7 : reponse
/// ListIdentity du module 1756-ENBT/A — 51 octets de command data (item
/// Identity 0x000C), que le parseur expose en `Raw`.
const LIST_IDENTITY_RESPONSE_FRAME_HEX: &str = concat!(
    "3ca9f42122f8001907243cca080045000073f258400034063ce00a0101a40a01",
    "01a7af12148e87b046928c05d68550181000f992000063003300000000000000",
    "000000000000c1debed10000000001000c002d0001000002af120a0101a40000",
    "00000000000001000c003a00040330008e4d52000b313735362d454e42542f41",
    "03"
);

/// `pcaps_exemple/protocols/ethernet_ip/cip-eth-set-2.pcap`, trame 1 :
/// reponse SendRRData (0x006F) — CPF Null Address + Unconnected Data
/// portant la reponse CIP « Set Attribute Single » (service 0x90, succes).
const SEND_RR_DATA_RESPONSE_FRAME_HEX: &str = concat!(
    "001d0999b22c0000bc3bd659080045000054e47440004006bffcc0a80a79c0a8",
    "0a69af12057a7d36809930cd408d50181000501300006f001400000102120000",
    "0000ec6d8601701ee10000000000000000000500020000000000b20004009000",
    "0000"
);

/// `pcaps_exemple/protocols/ethernet_ip/cip_unlock_cpu.pcap`, trame 1 :
/// requete SendUnitData (0x0070) — CPF Connected Address + Connected Data
/// (sequence CIP 7244, service 0x4C sur la classe 0x8E).
const SEND_UNIT_DATA_FRAME_HEX: &str = concat!(
    "0000bc2d83fe001d0999b22c080045000060858f40008006ded6c0a80a69c0a8",
    "0a78041eaf12e16d17717e687ae65018ffff9684000070002000000102120000",
    "00000000000000000000000000000000000001000200a1000400016b0700b100",
    "0c004c1c4c04208e240120742401"
);

/// Les quatre trames sont Ethernet (14) + IPv4 sans options (20) + TCP sans
/// options (20) : le payload d'encapsulation EtherNet/IP commence a
/// l'octet 54.
const TCP_PAYLOAD_OFFSET: usize = 54;

fn frame(hex_fixture: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(hex_fixture).expect("invalid test hex fixture");
    assert_eq!(
        bytes.len(),
        expected_len,
        "fixture length must match capture"
    );
    bytes
}

/// Verifie la chaine complete : la trame est decodee en `PacketFlow`, le
/// flux est etiquete EtherNet/IP sur TCP avec les ports attendus, puis le
/// payload TCP est retourne pour l'inspection champ a champ.
fn assert_flow_is_ethernet_ip(bytes: &[u8], source_port: u16, destination_port: u16) -> Vec<u8> {
    let flow = parse(LinkType::ETHERNET, bytes).expect("captured frame decodes");

    let transport = flow.transport.as_ref().expect("TCP transport");
    assert_eq!(transport.protocol, TransportProtocol::Tcp);
    assert_eq!(transport.source_port, Some(source_port));
    assert_eq!(transport.destination_port, Some(destination_port));

    assert_eq!(
        flow.application
            .expect("an application layer is detected")
            .application_protocol,
        "EtherNet/IP"
    );

    bytes[TCP_PAYLOAD_OFFSET..].to_vec()
}

#[test]
fn real_list_identity_request_decodes_with_an_empty_body() {
    let bytes = frame(LIST_IDENTITY_REQUEST_FRAME_HEX, 78);
    let payload = assert_flow_is_ethernet_ip(bytes.as_slice(), 5262, 44818);

    let packet = EtherNetIpPacket::try_from(payload.as_slice()).expect("real ListIdentity request");

    // tshark : enip.command == 0x0063, enip.length == 0, enip.session == 0,
    // enip.status == 0, enip.options == 0.
    assert_eq!(packet.header.command, EtherNetIpCommand::ListIdentity);
    assert_eq!(packet.header.command.name(), "ListIdentity");
    assert_eq!(packet.header.length, 0);
    assert_eq!(packet.header.session_handle, 0);
    assert_eq!(packet.header.status, 0);
    // Sender context reel non nul : le scanner y a mis un cookie opaque.
    assert_eq!(
        packet.header.sender_context,
        &[0x00, 0x00, 0x00, 0x00, 0xC1, 0xDE, 0xBE, 0xD1]
    );
    assert_eq!(packet.header.options, 0);

    assert!(matches!(packet.command_data, EtherNetIpCommandData::Empty));
}

#[test]
fn real_list_identity_response_exposes_the_identity_item_as_raw_data() {
    let bytes = frame(LIST_IDENTITY_RESPONSE_FRAME_HEX, 129);
    let payload = assert_flow_is_ethernet_ip(bytes.as_slice(), 44818, 5262);

    let packet =
        EtherNetIpPacket::try_from(payload.as_slice()).expect("real ListIdentity response");

    // tshark : enip.length == 51 ; la reponse porte le meme sender context
    // que la requete (echo du cookie du client).
    assert_eq!(packet.header.command, EtherNetIpCommand::ListIdentity);
    assert_eq!(packet.header.length, 51);
    assert_eq!(packet.header.session_handle, 0);
    assert_eq!(packet.header.status, 0);
    assert_eq!(
        packet.header.sender_context,
        &[0x00, 0x00, 0x00, 0x00, 0xC1, 0xDE, 0xBE, 0xD1]
    );

    // Le decodage CIP de l'item Identity n'est pas implemente : le parseur
    // doit exposer les 51 octets tels quels, sans les tronquer.
    let EtherNetIpCommandData::Raw(raw) = packet.command_data else {
        panic!("expected raw ListIdentity command data");
    };
    assert_eq!(raw, &payload[24..]);
    assert_eq!(raw.len(), 51);
    // Structure verifiee par tshark : 1 item, type 0x000C (Identity),
    // longueur 45, nom de produit "1756-ENBT/A", etat 3.
    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), 1);
    assert_eq!(u16::from_le_bytes([raw[2], raw[3]]), 0x000C);
    assert_eq!(u16::from_le_bytes([raw[4], raw[5]]), 45);
    assert_eq!(&raw[39..50], b"1756-ENBT/A");
    assert_eq!(raw[50], 3);
}

#[test]
fn real_send_rr_data_response_decodes_its_common_packet_format() {
    let bytes = frame(SEND_RR_DATA_RESPONSE_FRAME_HEX, 98);
    let payload = assert_flow_is_ethernet_ip(bytes.as_slice(), 44818, 1402);

    let packet = EtherNetIpPacket::try_from(payload.as_slice()).expect("real SendRRData response");

    // tshark : enip.length == 20, enip.session == 0x12020100,
    // enip.timeout == 5, deux items CPF (0x0000 puis 0x00B2).
    assert_eq!(packet.header.command, EtherNetIpCommand::SendRrData);
    assert_eq!(packet.header.length, 20);
    assert_eq!(packet.header.session_handle, 0x1202_0100);
    assert_eq!(packet.header.status, 0);
    assert_eq!(
        packet.header.sender_context,
        &[0xEC, 0x6D, 0x86, 0x01, 0x70, 0x1E, 0xE1, 0x00]
    );
    assert_eq!(packet.header.options, 0);

    let EtherNetIpCommandData::CommonPacketFormat(cpf) = packet.command_data else {
        panic!("expected common packet format");
    };
    assert_eq!(cpf.interface_handle, 0);
    assert_eq!(cpf.timeout, 5);
    assert_eq!(cpf.items.len(), 2);
    // Null Address Item : adresse vide d'un echange unconnected.
    assert_eq!(cpf.items[0].type_id, 0x0000);
    assert!(cpf.items[0].data.is_empty());
    // Unconnected Data Item : reponse CIP Set Attribute Single (0x10 | 0x80),
    // statut general 0x00 (succes).
    assert_eq!(cpf.items[1].type_id, 0x00B2);
    assert_eq!(cpf.items[1].data, &[0x90, 0x00, 0x00, 0x00]);
}

#[test]
fn real_send_unit_data_request_decodes_its_connected_items() {
    let bytes = frame(SEND_UNIT_DATA_FRAME_HEX, 110);
    let payload = assert_flow_is_ethernet_ip(bytes.as_slice(), 1054, 44818);

    let packet = EtherNetIpPacket::try_from(payload.as_slice()).expect("real SendUnitData request");

    // tshark : enip.length == 32, enip.session == 0x12020100,
    // enip.timeout == 1, items 0x00A1 (connid 0x00076B01) puis 0x00B1
    // (sequence CIP 7244).
    assert_eq!(packet.header.command, EtherNetIpCommand::SendUnitData);
    assert_eq!(packet.header.length, 32);
    assert_eq!(packet.header.session_handle, 0x1202_0100);
    assert_eq!(packet.header.status, 0);
    assert_eq!(packet.header.sender_context, &[0u8; 8]);
    assert_eq!(packet.header.options, 0);

    let EtherNetIpCommandData::CommonPacketFormat(cpf) = packet.command_data else {
        panic!("expected common packet format");
    };
    assert_eq!(cpf.interface_handle, 0);
    assert_eq!(cpf.timeout, 1);
    assert_eq!(cpf.items.len(), 2);
    // Connected Address Item : l'identifiant de connexion O->T.
    assert_eq!(cpf.items[0].type_id, 0x00A1);
    assert_eq!(cpf.items[0].data, &0x0007_6B01_u32.to_le_bytes());
    // Connected Data Item : compteur de sequence CIP puis requete (service
    // 0x4C, chemin classe 0x8E / instance 0x2474 / attribut 0x2474...).
    assert_eq!(cpf.items[1].type_id, 0x00B1);
    assert_eq!(cpf.items[1].data.len(), 12);
    assert_eq!(
        u16::from_le_bytes([cpf.items[1].data[0], cpf.items[1].data[1]]),
        7244
    );
    assert_eq!(cpf.items[1].data[2], 0x4C);
}
