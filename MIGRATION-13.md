# Migrer vers packet_parser 13.0.0

La 13.0.0 est publiée le 2026-11-17 ; la version précédente est la
12.1.0. Ses cinq ruptures ont été fusionnées sur `main` une à une, chacune
avec son entrée ci-dessous.

Ce guide a une entrée par rupture, avec l'avant, l'après et la raison. Sa
liste est recoupée avec `cargo semver-checks`, lancé contre la 12.1.0.
L'outil ne voit pas tout : il signale un `#[non_exhaustive]` ajouté, pas le
type d'un champ qui change. La première moitié de #275 lui échappe donc, et
c'est la suite de tests qui l'a trouvée.

## `CorruptedLayer.error` est une erreur typée (#275)

**État : publié en 13.0.0.** Le champ portait le texte de l'erreur. Il
porte maintenant l'erreur.

```rust
// 12.x
pub struct CorruptedLayer {
    pub layer: CorruptedLayerKind,
    pub error: String,
}

// 13.0
#[non_exhaustive]
pub struct CorruptedLayer {
    pub layer: CorruptedLayerKind,
    pub error: CorruptedLayerError,
}

#[non_exhaustive]
pub enum CorruptedLayerError {
    Internet(InternetError),
    Transport(TransportError),
}
```

`CorruptedLayerError` est réexporté à la racine, à côté de `CorruptedLayer`
et de `CorruptedLayerKind`. `InternetError` et `TransportError` sont dans
`packet_parser::errors::internet` et `packet_parser::errors::transport`.

### Lire le texte

`Display` rend le texte d'avant, à l'octet près.

```rust
// 12.x
let text: &str = &corrupted.error;

// 13.0
let text: String = corrupted.error.to_string();
println!("{}", corrupted.error); // sans allocation
```

Le compilateur signale chaque site : `expected String, found
CorruptedLayerError` (E0308), ou `no method named as_str` et `is_empty`
(E0599).

### Trier par cause

C'est ce que la rupture apporte : un `match`, là où il fallait chercher un
mot dans un message.

```rust
use packet_parser::CorruptedLayerError;
use packet_parser::errors::internet::{InternetError, ipv4::Ipv4Error};
use packet_parser::errors::transport::{TransportError, tcp::TcpError};

match &corrupted.error {
    CorruptedLayerError::Transport(TransportError::TcpError(
        TcpError::InvalidFlags { .. } | TcpError::ReservedBitsSet { .. },
    )) => { /* anomalie TCP : la couche transport est gardée */ }
    CorruptedLayerError::Transport(TransportError::TcpError(TcpError::PacketTooShort)) => {
        /* en-tête TCP tronqué */
    }
    CorruptedLayerError::Internet(InternetError::Ipv4Error(
        Ipv4Error::InvalidTotalLength { expected, actual, .. },
    )) => { /* longueur annoncée au-delà de la trame */ }
    _ => { /* les enums sont #[non_exhaustive] : garder un bras par défaut */ }
}
```

Les causes les plus fréquentes, et la variante qui les porte :

| Cause | Variante |
|---|---|
| En-tête IPv4 tronqué | `Internet(Ipv4Error(InvalidLength { .. }))` |
| En-tête IPv6 tronqué | `Internet(Ipv6Error(InvalidLength { .. }))` |
| Total Length IPv4 au-delà de la trame | `Internet(Ipv4Error(InvalidTotalLength { .. }))` |
| Version IP qui n'est pas 4 | `Internet(Ipv4Error(InvalidVersion(_)))` |
| IHL invalide | `Internet(Ipv4Error(InvalidHeaderLength(_)))` |
| En-tête TCP tronqué | `Transport(TcpError(PacketTooShort))` |
| Data offset TCP sous cinq mots | `Transport(TcpError(InvalidDataOffset(_)))` |
| SYN et FIN ensemble | `Transport(TcpError(InvalidFlags { .. }))` |
| Bits réservés TCP non nuls | `Transport(TcpError(ReservedBitsSet { .. }))` |
| En-tête UDP tronqué | `Transport(UdpError(PacketTooShort { .. }))` |
| Longueur UDP incohérente | `Transport(UdpError(InvalidLength { .. }))` |
| Trame PROFINET refusée | `Internet(ProfinetError(_))` |

`layer` reste là et dit la même chose que la variante de premier niveau :
`Internet` ou `Transport`.

### Construire un `CorruptedLayer`

Le littéral ne compile plus hors de la crate (E0639 : `cannot create
non-exhaustive struct using struct expression`). La valeur se construit à
partir de son erreur, et `layer` s'en déduit.

```rust
// 12.x
let corrupted = CorruptedLayer {
    layer: CorruptedLayerKind::Transport,
    error: "TCP error: Invalid TCP flags 0x03: SYN and FIN are both set".to_string(),
};

// 13.0
let corrupted = CorruptedLayer::from(TransportError::TcpError(TcpError::InvalidFlags {
    flags: 0x03,
}));
```

Une fixture ne peut donc plus porter un texte quelconque : elle porte une
erreur que la crate sait rendre. Pour un texte libre, deux variantes en
acceptent un, avec leur préfixe : `InternetError::InvalidFormat(String)`
(« Invalid packet format: … ») et `TransportError::InvalidTcpPacket(String)`
(« Invalid TCP packet: … »).

Qui recopie le rapport dans son propre type écrit `error:
corrupted.error.to_string()` là où il écrivait `error:
corrupted.error.clone()`.

### Ce qui ne change pas

- **Le JSON.** `CorruptedLayerError` se sérialise par son texte : la clé
  `error` porte la même chaîne, sous le même nom. Vérifié en sérialisant
  chaque trame du corpus avec la 12.1.0 puis avec ce code : 387 161 trames,
  dont 397 corrompues, et 2 426 corruptions synthétiques de couche 4
  (troncatures et mutations d'un octet d'un en-tête TCP et UDP). Les deux
  sorties sont identiques octet pour octet.
- Les textes d'erreur, `CorruptedLayerKind`, et le type de
  `PacketFlow::corrupted` et de `PacketFlowOwned::corrupted`
  (`Option<CorruptedLayer>`).
- Ce que `parse` rapporte, et quand : mêmes trames, mêmes couches gardées.

### Ce qui change aussi

- Les enums d'erreur des couches 3 et 4 dérivent `Clone`, `PartialEq`, `Eq`
  et `Hash`, pour que `PacketFlow` garde les siens : `InternetError`,
  `ArpError`, `Ipv4Error`, `Ipv6Error`, `ProfinetPacketError`,
  `GooseParseError`, `LldpParseError`, `PtpPacketParseError`,
  `TransportError`, `TcpError`, `UdpError`, `EspError`, `IcmpError` et
  `Icmpv6Error`. Ce sont des ajouts.
- `PacketFlow` passe de 440 à 456 octets : `CorruptedLayerError` fait 40
  octets, une `String` en faisait 24.

### Raison

Le moteur avait l'erreur typée en main et l'aplatissait par `to_string()`.
L'appelant ne pouvait distinguer un en-tête tronqué d'un SYN+FIN qu'en
lisant un message, dont la formulation n'est couverte ni par semver ni par
un test. Et chaque paquet corrompu payait l'allocation d'une `String`,
alors qu'un trafic malformé est justement le cas hostile.

Mesure sur le bench du dépôt (`benches/`), deux passes alternées de la
12.1.0 et de ce code sur la même machine :

| Cas | 12.1.0 | 13.0 | Écart |
|---|---|---|---|
| `frame/corrupted_ipv4_total_length`, trame réelle | 363 et 368 ns | 106 et 107 ns | −71 % |
| `frame/corrupted_tcp_truncated`, synthétique | 201 et 198 ns | 119 et 118 ns | −40 % |
| `frame/corrupted_tcp_syn_fin`, synthétique | 331 et 332 ns | 130 et 121 ns | −62 % |
| `frame/tcp_pure_ack`, trame saine | 129 et 141 ns | 128 et 128 ns | dans le bruit |
| `corpus/subset`, 775 trames saines | 302 et 301 µs | 287 et 291 µs | −4 % |

Un paquet corrompu coûte maintenant ce que coûte un ACK sain. Les trois
cas `corrupted_*` ont été ajoutés au bench pour cette mesure : le
sous-ensemble `corpus/subset` n'a aucune trame corrompue, et le corpus
entier n'en a qu'en couche 3 (397 trames sur 387 161), d'où les deux cas
synthétiques de couche 4.

Les 16 octets de plus dans `PacketFlow` ne se voient pas sur les trames
saines. L'écart de `corpus/subset` n'est pas à mettre au crédit du
changement : son chemin n'est pas touché, et d'une passe à l'autre du même
binaire une trame saine varie davantage (`frame/dns` : 894 puis 758 ns
avec la 12.1.0).

## QUIC : le numéro de paquet n'est plus lu, `LengthFieldTooSmall` porte `min` (#293)

**État : publié en 13.0.0.** Dans un Initial, un 0-RTT ou un Handshake, la
protection d'en-tête (RFC 9001 §5.4) masque le numéro de paquet et les
quatre bits bas de l'octet 0, dont sa longueur. La 12.x les lisait quand
même : `packet_number` et la longueur prise aux bits bas étaient du bruit
sur tout paquet réel, et la charge commençait de 0 à 3 octets trop tôt ou
trop tard. Sur les vecteurs de la RFC 9001, l'Initial client (A.2) sortait
le numéro 123 au lieu de 2, l'Initial serveur (A.3) 0xc0d95a48 au lieu
de 1.

### L'erreur

`QuicError::LengthFieldTooSmall` comparait Length à cette longueur
protégée. Elle compare maintenant Length au minimum qu'impose
l'échantillon de la protection d'en-tête : 4 octets de numéro de paquet
supposés, puis 16 octets d'échantillon (RFC 9001 §5.4.2, « An endpoint
MUST discard packets that are not long enough to contain a complete
sample »). La constante est `QUIC_MIN_PROTECTED_LENGTH`, 20.

```rust
// 12.x
QuicError::LengthFieldTooSmall { length_field: u64, pn_length: u8 }

// 13.0
QuicError::LengthFieldTooSmall { length_field: u64, min: u64 }
```

Un motif qui nomme `pn_length` ne compile plus (E0026) ; `{ .. }` ne
change pas.

### Ce qui change sans erreur de compilation

| Champ | 12.x | 13.0 |
|---|---|---|
| `QuicLongHeader::packet_number` | `Some(n)`, lu sur les octets protégés | toujours `None` |
| `QuicLongHeader::pn_length` | présenté comme la longueur du numéro | mêmes bits, documentés comme protégés |
| `EncryptedPayload` d'un Initial, Handshake, 0-RTT | après `pn_length` octets | dès le champ Length franchi : numéro de paquet protégé compris, `length_field` octets |
| Length de 1 à 19 | accepté | refusé (`LengthFieldTooSmall`) |

Qui retire lui-même la protection d'en-tête (il a les clés) trouve le
numéro de paquet au début de `EncryptedPayload`, et l'échantillon à
l'octet 4 de cette même tranche.


## `ApplicationProtocol` a une variante `Custom(&'static str)` (#319)

**État : publié en 13.0.0.** Une application peut ajouter ses propres
parseurs, pour les protocoles que la crate ne décode pas (trait
`ApplicationParser`, `ParseConfig::with_parser`). Ce qu'ils reconnaissent
est étiqueté `ApplicationProtocol::Custom(label)`. Cette variante porte une
donnée : les autres n'ont plus de discriminant défini, et un cast `as` ne
compile plus.

```rust
// 12.x
let index = flow_protocol as usize; // compilait

// 13.0
let index = ApplicationProtocol::ALL
    .iter()
    .position(|protocol| *protocol == flow_protocol); // None pour Custom
```

Le cast refusé est l'erreur E0605 (`non-primitive cast`). Pour une clé de
table, `label()` ou `std::mem::discriminant` conviennent aussi.

### Ce qui change sans erreur de compilation

- `ALL` ne liste que les protocoles intégrés : `Custom` n'y est pas.
- `FromStr` ne relit pas une étiquette ajoutée : `"ACME".parse()` reste une
  erreur `UnknownApplicationLabel`. Seule la configuration qui a enregistré
  le parseur connaît l'étiquette (`ParseConfig::parser`).
- Un `match` exhaustif était déjà impossible hors de la crate
  (`#[non_exhaustive]`) : le bras `_` reçoit `Custom`.
- Sans parseur enregistré, rien ne change : `parse`, `parse_with` et
  `classify_payload_with` ne produisent jamais `Custom`.

## NTP : les horodatages sont des `NtpTimestamp`, plus des `DateTime<Utc>` (#315)

**État : publié en 13.0.0.** La crate ne dépend plus de `chrono`, non
maintenu depuis le 2026-11-17 (RUSTSEC-2026-0543, sans faille). Les quatre
horodatages de `NtpPacket` sont désormais un type de la crate,
`packet_parser::parse::application::protocols::ntp::NtpTimestamp`, qui
garde les deux champs du fil.

```rust
// 12.x
pub reference_timestamp: chrono::DateTime<chrono::Utc>, // idem pour originate, receive, transmit

// 13.0
pub reference_timestamp: NtpTimestamp,

#[non_exhaustive]
pub struct NtpTimestamp {
    pub seconds: u32,  // depuis le début de l'ère
    pub fraction: u32, // en 2^-32 s
}
```

Ce que fournissait `DateTime<Utc>` a son équivalent :

| 12.x | 13.0 |
|---|---|
| `t.timestamp()` | `t.unix_seconds()` |
| `t.timestamp_subsec_nanos()` | `t.subsec_nanos()` |
| `t.to_rfc3339_opts(SecondsFormat::Nanos, true)` | `t.to_string()`, au caractère près |
| `t == Utc.timestamp_opt(0, 0).unwrap()` (horodatage inconnu) | `t.is_null()` |
| `a < b` | `a < b`, dans l'ordre du temps, ères comprises |
| un `SystemTime` | `t.to_system_time()` |

Qui veut garder `chrono` reconstruit la date de son côté :
`Utc.timestamp_opt(t.unix_seconds(), t.subsec_nanos())`.

Les dates ne changent pas. L'ère se choisit comme avant, comme tshark
(RFC 4330 §3) : bit de poids fort à 1, ère 0 (1968 à 2036) ; à 0, ère 1
(2036 à 2104). Un horodatage nul est daté de l'époque Unix.
`tests/ntp_golden.rs` le vérifie contre tshark, au caractère près, sur
chaque datagramme NTP du corpus.

`NtpPacketParseError::TimestampConversionError { seconds, nanos }`
disparaît. Elle signalait une date que `chrono` ne savait pas représenter,
ce qui ne se produisait jamais sur 64 bits de secondes. Un motif qui la
nomme ne compile plus (E0599).
