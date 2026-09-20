# Migrer vers packet_parser 11.0.0

Une entrée par rupture : avant, après, raison. Ce guide se remplit lot par
lot pendant le chantier de l'epic #76 ; la liste est recoupée avec
`cargo semver-checks` avant publication.

## GIOP

Le décodeur GIOP passe d'un header + Request à tout le protocole. Rien ne
change pour qui ne lit que l'étiquette `"GIOP"` du `PacketFlow` — sinon que
davantage de trames la portent (premier segment d'un message fragmenté par
TCP).

### `GiopReply` porte le message décodé

```rust
// 10.x : struct vide
if let GiopMessage::Reply(_) = packet.payload { /* rien à lire */ }

// 11.0
if let GiopMessage::Reply(reply) = &packet.payload {
    println!("{} {:?}", reply.request_id, reply.reply_status);
    if let GiopReplyDetail::LocationForward(ior) = &reply.detail
        && let Some(iiop) = ior.iiop()
    {
        println!("redirigé vers {}:{}", iiop.host, iiop.port);
    }
}
```

### `GiopMessage` : nouveaux types, et `Other` change de sens

En 10.x, `Other` couvrait tout ce qui n'était ni Request ni Reply. En 11.0
chaque type a sa variante (`CancelRequest`, `LocateRequest`, `LocateReply`,
`CloseConnection`, `MessageError`, `Fragment`) ; `Other` signifie « type
valide, body illisible ». L'enum est `#[non_exhaustive]` : un `match` externe
doit garder un bras `_`.

### `TargetAddress`

```rust
// 10.x
TargetAddress::ProfileAddr(profile_data) => …
TargetAddress::ReferenceAddr(raw_span) => …

// 11.0
TargetAddress::ProfileAddr(profile) => { profile.tag; profile.profile_data; }
TargetAddress::ReferenceAddr { selected_profile_index, ior } => …
```

### Messages tronqués : `Ok` + `truncated`, plus `Err(TruncatedBody)`

```rust
// 10.x
match GiopPacket::try_from(payload) {
    Err(GiopParseError::TruncatedBody { .. }) => /* message > segment TCP */,
    …
}

// 11.0
let packet = GiopPacket::try_from(payload)?;
if packet.truncated { /* body partiel : packet.wire_len() octets présents */ }
```

Raison : un message GIOP dépasse couramment le MSS ; le rejeter faisait
sortir son premier segment en `Unknown`, alors qu'il porte l'en-tête complet
(request id, opération, object key).

### `stub_data` sans le padding

En GIOP 1.2 le stub data est aligné sur 8 octets. Le padding était compté
dans `GiopRequest::stub_data` ; il ne l'est plus. Qui décodait les arguments
CDR à partir de `stub_data` doit retirer son propre saut de padding.

### Les domaines dépendent de la version du message

`LOCATION_FORWARD_PERM` et `NEEDS_ADDRESSING_MODE` (Reply),
`OBJECT_FORWARD_PERM`, `LOC_SYSTEM_EXCEPTION` et `LOC_NEEDS_ADDRESSING_MODE`
(LocateReply), ainsi que le message `Fragment`, ne sont définis qu'à partir
de GIOP 1.2 (1.1 pour `Fragment`). Le décodeur les refuse désormais sur un
message qui déclare une version antérieure — un `GiopReply` valide mais
contradictoire n'est plus exposé. La conversion exige donc la version :

```rust
// 10.x / première version de cette branche
let status = GiopReplyStatus::try_from(raw)?;

// 11.0
let status = GiopReplyStatus::from_wire(raw, header.minor_version)?;
let status = GiopLocateStatus::from_wire(raw, header.minor_version)?;
let reply = GiopLocateReply::parse(body, little_endian, header.minor_version)?;
```

### Erreurs et `checks`

- `GiopParseError::UnknownTargetDiscriminator(u8)` → `(u16)`.
- `GiopParseError::UnknownReplyStatus(u32)` → `{ status, minor_version }` ;
  idem `UnknownLocateStatus`. Nouvelle variante `MessageTypeNotInVersion`.
- `GiopParseError::TruncatedBody` supprimée (voir ci-dessus).
- `GiopParseError` est `#[non_exhaustive]` : bras `_` requis.
- `checks::application::giop::extract_message_length(payload)` →
  `extract_message_size(payload, little_endian)`.
- `checks::application::giop::validate_total_length` supprimée.
- `validate_target_discriminator(u8)` → `(u16)`.

### Construction des types

Tous les types GIOP sont `#[non_exhaustive]` : ils ne se construisent plus
par littéral hors de la crate, et se déstructurent avec `..`.

## Purge de la surface publique

### `checks` n'est plus public ; les checksums déménagent

```rust
// 10.x
use packet_parser::checks::checksum::verify_tcp_checksum;

// 11.0
use packet_parser::checksum::verify_tcp_checksum;
```

Le reste de `packet_parser::checks` (les `validate_*` / `extract_*` des
parseurs) n'a pas de remplaçant : c'étaient des détails d'implémentation.
Pour savoir si des octets sont un message valide, passer par le décodeur
(`XxxPacket::try_from`) ; pour reconnaître S7CommPlus,
`S7CommPacket::detect_protocol_version`.

### `PacketFlow::to_owned()` → `to_owned_flow()`

```rust
let owned: PacketFlowOwned = flow.to_owned_flow();   // conversion lossy
let copy: PacketFlow<'_> = flow.clone();              // vrai clone
```

Attention : après migration, un `flow.to_owned()` oublié **compile encore**
— il résout désormais vers `ToOwned::to_owned` et rend un `PacketFlow`, plus
un `PacketFlowOwned`. Le compilateur le signale dès que le résultat est
utilisé comme un `PacketFlowOwned`.

### `parse_timing`

L'API ne dépend plus de la feature : `ParseTiming` a toujours cinq champs
`u64`, `parse_timed` et `PacketFlow::try_from_timed` existent toujours. Sans
la feature ils parsent normalement et laissent les mesures à zéro. Les
`#[cfg(feature = "parse_timing")]` côté consommateur autour de ces appels
peuvent disparaître.

Supprimés, sans remplaçant (aucun n'avait d'usage hors de la crate) :
`timing::now`, `timing::elapsed_ns`, `timing::ParseReport`,
`timing::LayerAttempt`, `time_block_ns!`.

### Code mort supprimé

| Supprimé | À la place |
|---|---|
| `ApplicationProtocol` | l'étiquette `Application::application_protocol`, et les décodeurs de `parse::application::protocols` |
| `ApplicationError::*ParseError` (9 variantes) | jamais émises ; seul `EmptyPacket` existe. L'enum est `#[non_exhaustive]` |
| `Transport::try_from(&[u8])` | `Transport::try_from_parts(protocole_ip, payload)` |
| `ParseError::PacketTooShort` | jamais émise |
| `ParsedPacketError` | `ParseError` (c'était un alias) |
| `QuicPacketType::Unknown` | jamais construite : les quatre types de Long Header sont nommés |
| feature `doc-diagrams` | vide depuis le retrait d'`aquamarine` ; la retirer de `features = [...]` |

### `Packet::packet_to_pcap`

```rust
packet.packet_to_pcap("capture.pcap")?;   // 10.x écrivait ./output.pcap
```

### Déprécié

`convert::hex_stream_to_bytes` panique sur une entrée invalide :
`try_hex_stream_to_bytes` rend un `Result`.

## Erreurs

### Tous les enums d'erreur sont `#[non_exhaustive]`

Un `match` exhaustif sur un enum d'erreur de `packet_parser::errors` doit
gagner un bras `_`. En contrepartie, les prochaines variantes d'erreur
arriveront en version mineure.

### TCP : SYN+FIN et bits réservés ne font plus disparaître le transport

C'est le changement de **comportement** le plus visible de la 11.0.0.

| Paquet | 10.x | 11.0 |
|---|---|---|
| SYN+FIN, ou bits réservés ≠ 0 | `transport: None`, `corrupted: Transport` (« Invalid TCP header length ») | `transport: Some(..)` avec ses ports, `corrupted: Transport` (« Invalid TCP flags 0x03: SYN and FIN are both set »), `application: None` |

```rust
// Distinguer corruption structurelle et anomalie sémantique
if let Some(corrupted) = &flow.corrupted
    && corrupted.layer == CorruptedLayerKind::Transport
{
    match &flow.transport {
        None => { /* en-tête illisible */ }
        Some(transport) => { /* anomalie : ports exploitables, paquet suspect */ }
    }
}
```

Qui comptait les flux sur `transport.is_some()` verra ces paquets
apparaître : c'est le but (corrélation de scans SYN+FIN). Qui veut les
écarter filtre sur `flow.corrupted`.

Côté décodeur : `TcpPacket::try_from` rend `Ok` sur ces segments ;
`TcpPacket::anomaly()` rend `Some(TcpError::InvalidFlags { .. })` ou
`Some(TcpError::ReservedBitsSet { .. })`. `TcpError::InvalidHeaderLength`
est supprimée.

### Erreurs de liaison : un seul chemin

```rust
// 10.x : deux variantes selon le LINKTYPE
Err(ParseError::InvalidDataLink(_))      // Ethernet
Err(ParseError::InvalidLinkLayer(_))     // RAW, SLL, SLL2

// 11.0 : une seule, pour tous
Err(ParseError::InvalidLinkLayer(LinkLayerError::Truncated {
    link_type, required, actual,
}))
```

`DataLinkError` existe toujours — c'est l'erreur de `DataLink::try_from`
appelé directement — mais n'est plus convertible en `ParseError`. Sa
variante `DataLinkTooShort(u8)` devient `DataLinkTooShort { required,
actual }` (`usize`).

## Champs et variantes

### `vlan_stack`

Nouveau champ sur `DataLink` et `DataLinkOwned`. `vlan` garde son sens (le
tag interne) : rien à changer pour qui ne lit que lui.

```rust
for tag in flow_data_link.vlan_stack.iter() { /* externe → interne */ }
let s_vlan = flow_data_link.vlan_stack.outer();
```

`DataLinkOwned` reste constructible en littéral, mais gagne un champ :

```rust
DataLinkOwned { destination_mac, source_mac, ethertype, vlan, vlan_stack: Vec::new() }
```

JSON : une clé `vlan_stack` (liste de `{id, pcp, dei}`) apparaît dans
`link_details` **uniquement** pour les trames à deux tags ou plus.

### `IpType::Broadcast`

`255.255.255.255` est classée `Broadcast` au lieu de `Public`. Un filtre
« trafic vers Internet » basé sur `IpType::Public` n'attrape plus la
diffusion limitée — c'était un faux positif.

### `#[non_exhaustive]` sur les types que le parseur construit

Pour 124 enums et structs de `packet_parser::parse` :

- un `match` sur un de ces enums doit avoir un bras `_` ;
- une déstructuration de struct doit finir par `..` ;
- ces structs ne se construisent plus par littéral hors de la crate.

Ne sont **pas** concernés, et restent constructibles : tout
`packet_parser::owned`, `VlanTag`, `CorruptedLayer`, `TlsVersion`,
`BridgeId`, `ParseTiming`, `convert::Packet`, ainsi que les types valeur
tuple (`MacAddress`, `Ethertype`, `LinkType`, `Dscp`, `DnsType`, …).
`Ecn` et `QuicPacketType`, fermés par construction, restent exhaustifs.

`IpType`, `CorruptedLayerKind` et `TransportProtocol` sont dans le lot : leurs
`match` côté consommateur ont besoin d'un bras `_` (`NetworkProtocol` l'était
déjà en 10.x).

