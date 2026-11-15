# Migrer vers packet_parser 12.0.0

La 12.0.0 n'est pas publiée. Elle regroupe en une seule majeure les
ruptures de la feature #209, toutes faites. Elle suit directement la
11.8.2 : aucune 11.x intermédiaire n'a porté d'alias ni de dépréciation
pour ces ruptures.

Ce guide a une entrée par rupture, avec l'avant, l'après et la raison. Sa
liste est recoupée avec `cargo semver-checks --baseline-version 11.8.2`.

## `Application::try_from(&[u8])` est retiré (#219)

**État : fait, non publié.** L'impl est retirée, avec la cascade interne
sans transport ni port qu'elle appelait. `classify_payload`, qui la
remplace, arrive dans la même version. Un appel restant ne compile plus :

```text
error[E0277]: the trait bound `packet_parser::Application: TryFrom<&[u8]>` is not satisfied
```

```rust
// 11.x : le payload seul
let label = Application::try_from(payload)?.application_protocol;

// 12.0 : le payload, avec le transport et les ports qui l'ont porté
let label = classify_payload(protocol, source_port, destination_port, payload)
    .map(|application| application.application_protocol);
```

À partir d'un `Transport` décodé par la crate :

```rust
let application = transport.payload.and_then(|payload| {
    classify_payload(
        transport.protocol,
        transport.source_port,
        transport.destination_port,
        payload,
    )
});
```

Qui appelle `parse` n'a rien à faire : l'étiquette est déjà dans
`PacketFlow::application`, et `classify_payload` rend la même.

### Ce qui change

- **Le type de retour.** `Option<Application>` remplace
  `Result<Application, ApplicationError>`. Un payload vide rend `None`, et
  plus `Err(ApplicationError::EmptyPacket)`. `None` aussi pour un protocole
  autre que TCP et UDP, et sur un port UDP réservé à mDNS (5353) ou à LLMNR
  (5355) qui porte autre chose. Un payload sondé sans succès reste `Some`,
  avec l'étiquette `"Unknown"`.
- **Les étiquettes.** Ce sont celles de `parse`. Sur le corpus de la crate
  (254 107 flux TCP et UDP à payload non vide), 9 307 changent :

  | Avant, avec `try_from` | Après, avec `classify_payload` | Flux |
  |---|---|---|
  | `Unknown` | le protocole que son port identifie (PTP, IKE, OpenVPN, IEC 104, NBSS, COTP…) ou le nom du tunnel (VXLAN, Geneve, GTP-U) | 8 004 |
  | `DNS` | `NBNS`, `mDNS` ou `LLMNR` : même format, seul le port les distingue | 1 246 |
  | `ModbusTCP` sur UDP 502 | `ModbusUDP` : la même enveloppe MBAP, sous l'étiquette de son transport (#257) | 38 |
  | `RADIUS` sur des segments MMS (TCP 102) | `COTP` | 13 |
  | `HTTP` sur des réponses SSDP hors du port 1900 | `Unknown` | 5 |
  | `NTP` sur une requête DNS de 48 octets | `DNS` | 1 |

- **Un port inconnu se passe `None`.** Les règles à port ne s'appliquent
  alors pas ; les signatures assez fortes pour s'en passer restent, chacune
  derrière sa garde de transport.
- **Sans transport, il n'y a plus d'entrée.** C'est le but : une étiquette
  donnée sans savoir si les octets venaient de TCP ou d'UDP était fausse
  trop souvent. Qui n'a vraiment que des octets peut interroger chaque
  hypothèse, `TransportProtocol::Tcp` puis `TransportProtocol::Udp`, et
  garder les deux réponses pour ce qu'elles sont.
- **« Decode As ».** `classify_payload_with` prend un `ParseConfig`, comme
  `parse_with`, et rend la même étiquette que lui.

### Trois différences avec `parse`

`classify_payload` reçoit un payload, pas une trame. Trois réponses de
`parse` tiennent à ce qu'elle ne voit pas :

- **Les drapeaux TCP.** `parse` ne sonde pas un segment dont les drapeaux
  sont anormaux (SYN+FIN, bits réservés) et laisse sa couche application
  vide. `classify_payload` classe ce payload comme un autre.
- **Les tunnels de niveau IP.** `parse` nomme GRE et IP-in-IP depuis
  l'en-tête IP. Ils n'ont pas de payload de transport : `classify_payload`
  rend `None` pour leurs protocoles, comme pour tout ce qui n'est ni TCP ni
  UDP.
- **L'imbrication des tunnels.** `parse` garde quatre niveaux de flux au plus
  et ne cherche plus de tunnel au dernier : un datagramme de tunnel qui s'y
  trouve est étiqueté par la table seule. `classify_payload` n'a pas de
  profondeur. Elle répond toujours comme pour un flux externe, et nomme le
  tunnel.

### Raison

`Application::try_from` ne voyait que des octets. Elle sautait toutes les
règles à port de la table de dispatch et n'appliquait aucune de ses gardes de
transport : une signature TCP pouvait étiqueter un datagramme UDP, et
l'inverse. C'était une seconde porte d'entrée publique qui ne répondait pas
comme `parse`, alors que la table existe pour supprimer ces faux positifs
(#29, #164). Elle ne se corrigeait pas sans changer de signature : le
transport et les ports ne sont pas dans `&[u8]`.

## `ApplicationError` et `ParseError::Application` sont retirés (#219)

**État : fait, non publié.**

`ApplicationError` n'avait plus qu'une variante, `EmptyPacket`, et seul
`Application::try_from` la rendait. L'impl partie, rien dans la crate ne
construit cette erreur. `ParseError::Application`, qui l'enveloppait, n'a
jamais été rendue par `parse`.

```rust
// 11.x
match Application::try_from(payload) {
    Err(ApplicationError::EmptyPacket) => { /* payload vide */ }
    Ok(application) => { /* … */ }
}

// 12.0 : un payload vide n'a pas de couche application
match classify_payload(protocol, source_port, destination_port, payload) {
    None => { /* payload vide, ou rien à classer */ }
    Some(application) => { /* … */ }
}
```

Un `match` sur `ParseError` qui nommait la variante `Application` perd ce
bras. L'enum est `#[non_exhaustive]` : le bras `_` existe déjà.

Les erreurs des décodeurs applicatifs (`errors::application::dns`,
`errors::application::tls`…) ne changent pas.

Raison : une erreur que rien ne rend est une promesse fausse dans une
signature. La 11.0.0 avait retiré de la même façon les neuf variantes
d'`ApplicationError` jamais construites (`MIGRATION-11.md`).

## Renommages (#220)

**État : fait, non publié.** Aucun comportement ne change, aucune
étiquette, aucun JSON.

| Ancien nom, retiré en 12.0 | Nouveau nom |
|---|---|
| `parse::application::protocols::copt` | `parse::application::protocols::cotp` |
| `errors::application::copt` | `errors::application::cotp` |
| `parse::data_link::mac_addres` | `parse::data_link::mac_address` |
| `errors::data_link::mac_addres` | `errors::data_link::mac_address` |
| `ike::PayloadType::NatDetection` | `ike::PayloadType::NatDiscovery` |
| `radius::AttributeType::MipHomeAgentAddress` | `radius::AttributeType::Mip6FeatureVector` |
| `radius::AttributeType::MipHomeAgentHost` | `radius::AttributeType::Mip6HomeLinkPrefix` |

```rust
// 11.8
use packet_parser::parse::application::protocols::copt::CotpHeader;
use packet_parser::parse::data_link::mac_addres::MacAddress;

match payload.kind {
    Some(PayloadType::NatDetection) => { /* … */ }
    _ => {}
}

// 12.0
use packet_parser::parse::application::protocols::cotp::CotpHeader;
use packet_parser::parse::data_link::mac_address::MacAddress;

match payload.kind {
    Some(PayloadType::NatDiscovery) => { /* … */ }
    _ => {}
}
```

Les types eux-mêmes ne changent pas de nom : `CotpHeader`, `CotpParseError`,
`MacAddress`, `MacParseError`, `Oui`. `packet_parser::MacAddress`, à la
racine de la crate, ne bouge pas.

### Ce qui change

- **Quatre chemins de modules.** L'ancien chemin ne compile plus. Une
  recherche de `copt` et de `mac_addres` dans le code appelant suffit.
- **Trois variantes.** Chacune prend son nouveau nom à la même position
  dans l'enum : les discriminants sont ceux de la 11.8.2, figés par test.
  Les deux types RADIUS avaient déjà ces noms en constantes associées
  depuis la 11.7.0 : qui les utilisait ne change rien.
- **Le texte de `{:?}`.** `Debug` rend le nom de la variante : en 12.0,
  `NatDiscovery`, `Mip6FeatureVector` et `Mip6HomeLinkPrefix`. Ces types ne
  sont pas sérialisés : le JSON de `owned` ne change pas.

### Raison

`copt` et `mac_addres` sont des fautes de frappe. Le registre IANA nomme les
payloads IKEv1 20 et 130 « NAT-D », NAT Discovery (RFC 3947), et les types
RADIUS 124 et 125 MIP6-Feature-Vector et MIP6-Home-Link-Prefix (RFC 5447),
pas une adresse ni un nom d'hôte (#191). Chacun de ces renommages est une
rupture ; ils sont groupés pour n'en faire qu'une.

## Trois éléments dépréciés sont retirés (#220)

**État : fait, non publié.** Chacun avertissait déjà à la compilation, et
son remplaçant existe en 11.8.2.

| Retiré | Déprécié depuis | Remplaçant |
|---|---|---|
| `SrvlocHeaderV1::encoding` (champ `u8`) | 11.5.0 | `SrvlocHeaderV1::char_encoding` (`u16`) |
| `convert::hex_stream_to_bytes` | 11.0.0 | `convert::try_hex_stream_to_bytes` |
| `S7CommPacket::MIN_SIZES` | sans version indiquée | `S7CommPacket::MIN_SIZE` |

```rust
// 11.x
let bytes = hex_stream_to_bytes(hex);            // panique sur une entrée invalide
let utf8 = header.encoding == 0;                 // l'octet de poids fort seul

// 12.0
let bytes = try_hex_stream_to_bytes(hex)?;       // Result<Vec<u8>, HexStreamError>
let utf8 = header.char_encoding == 106;          // MIBenum IANA sur deux octets
```

`SrvlocHeaderV1` est une struct exhaustive : qui la construit ou la
déstructure champ par champ retire `encoding`.

Raison : `encoding` ne lisait qu'un octet d'un champ de deux (RFC 2165 §7)
et valait 0 pour tout MIBenum inférieur à 256, UTF-8 compris ;
`hex_stream_to_bytes` paniquait sur une entrée invalide ; `MIN_SIZES` était
une faute de frappe.

## `Application.protocol` est un enum (#217)

**État : fait, non publié.** Le champ texte
`Application::application_protocol` est remplacé par
`Application::protocol`, de type `ApplicationProtocol`. Il n'y a pas de
transition en 11.x.

```rust
// 11.x : une chaîne
match application.application_protocol {
    "IEC 104" => { /* … */ }
    "ModbusTCP" => { /* … */ }
    _ => {}
}

// 12.0 : un enum
match application.protocol {
    ApplicationProtocol::Iec104 => { /* … */ }
    ApplicationProtocol::ModbusTcp => { /* … */ }
    _ => {}
}
```

Qui veut encore la chaîne l'obtient par `label()` :

```rust
let label: &'static str = application.protocol.label();   // "IEC 104"
let protocol: ApplicationProtocol = "IEC 104".parse()?;    // l'inverse
```

### Ce qui change

- **Le champ.** `application_protocol: &'static str` devient
  `protocol: ApplicationProtocol`. Un appel mécanique : remplacer
  `.application_protocol` par `.protocol.label()` garde le code tel qu'il
  était, chaîne pour chaîne.
- **L'enum.** 54 variantes, une par étiquette : celles de la table de
  dispatch, les tunnels (`Vxlan`, `Geneve`, `GtpU`, `Capwap`, `Gre`,
  `IpInIp`), `Stp` et `Unknown`. Il est `#[non_exhaustive]` : un `match`
  garde un bras `_`, et un nouveau protocole sera une mineure.
- **`FromStr` est strict.** Un texte qui n'est l'étiquette d'aucune variante
  rend `UnknownApplicationLabel`, pas `ApplicationProtocol::Unknown`. La
  casse compte : `"mdns"` n'est pas `"mDNS"`.
- **`Application` dérive `PartialEq`, `Eq` et `Hash`**, avec le même
  comportement que ses impls écrites à la main.

### Ce qui ne change pas

- **Aucune étiquette ne change de texte.** `label()`, `Display` et la
  sérialisation rendent les chaînes de la 11.8.2 à l'octet près, figées par
  un test.
- **Le JSON.** La clé reste `application_protocol`, dans la forme empruntée
  comme dans `owned`. `ApplicationOwned::protocol` reste une `String`.

### Raison

Un `match` sur une chaîne n'a pas d'exhaustivité, une faute de frappe y est
silencieuse, et renommer une étiquette était une rupture que
`cargo semver-checks` ne pouvait pas voir. La table de dispatch porte
maintenant l'enum : une étiquette sans variante ne compile pas.

Un enum du même nom existait avant la 11.0.0, qui l'avait retiré comme code
mort (`MIGRATION-11.md`) : rien ne le produisait. Celui-ci est ce que
`parse` rend.

