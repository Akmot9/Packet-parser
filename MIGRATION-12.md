# Migrer vers packet_parser 12.0.0

La 12.0.0 n'est pas publiée. Elle regroupera en une seule majeure les
ruptures de la feature #209, et ne sortira pas avant mars 2027, fin de la
fenêtre de stabilité ouverte par la 11.0.0 (`ROADMAP.md` §4).

Ce guide s'écrit avant chaque rupture, pas après : une entrée par rupture,
avec l'avant, l'après et la raison. Sa liste sera recoupée avec
`cargo semver-checks` avant la publication.

## `Application::try_from(&[u8])` est retiré (#219)

**État : annoncé.** L'impl existe encore en 11.x. `classify_payload`, qui la
remplace, arrive avec la prochaine version 11.x : la migration peut se faire
avant la 12.0. Le compilateur ne préviendra pas, parce que rustc refuse
`#[deprecated]` sur un impl de trait.

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
  | `ModbusTCP` sur UDP 502 | `Unknown` : la règle Modbus n'admet que TCP | 38 |
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

## Renommages (#220)

**État : annoncé.** Les nouveaux noms arrivent avec la prochaine version
11.x, et les anciens restent jusqu'à la 12.0 : la migration peut se faire
avant. Aucun comportement ne change, aucune étiquette, aucun JSON.

| Ancien nom, retiré en 12.0 | Nouveau nom | Le compilateur prévient en 11.x |
|---|---|---|
| `parse::application::protocols::copt` | `parse::application::protocols::cotp` | non |
| `errors::application::copt` | `errors::application::cotp` | non |
| `parse::data_link::mac_addres` | `parse::data_link::mac_address` | non |
| `errors::data_link::mac_addres` | `errors::data_link::mac_address` | non |
| `ike::PayloadType::NatDetection` | `ike::PayloadType::NatDiscovery` | oui |
| `radius::AttributeType::MipHomeAgentAddress` | `radius::AttributeType::Mip6FeatureVector` | oui, depuis la 11.7.0 |
| `radius::AttributeType::MipHomeAgentHost` | `radius::AttributeType::Mip6HomeLinkPrefix` | oui, depuis la 11.7.0 |

```rust
// 11.8
use packet_parser::parse::application::protocols::copt::CotpHeader;
use packet_parser::parse::data_link::mac_addres::MacAddress;

match payload.kind {
    Some(PayloadType::NatDetection) => { /* … */ }
    _ => {}
}

// 12.0, et déjà valable en 11.x
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

- **Quatre chemins de modules.** En 11.x, l'ancien chemin est un alias du
  nouveau. rustc ne propage pas `#[deprecated]` à travers un `pub use` :
  qui passe par `copt` ou `mac_addres` ne reçoit aucun avertissement. Une
  recherche de ces deux mots dans le code appelant suffit.
- **Trois variantes.** En 11.x, le nouveau nom est une constante associée
  qui vaut l'ancienne variante, en valeur comme en motif de `match`. En
  12.0, la variante prend ce nom, à la même position dans l'enum.

### Raison

`copt` et `mac_addres` sont des fautes de frappe. Le registre IANA nomme les
payloads IKEv1 20 et 130 « NAT-D », NAT Discovery (RFC 3947), et les types
RADIUS 124 et 125 MIP6-Feature-Vector et MIP6-Home-Link-Prefix (RFC 5447),
pas une adresse ni un nom d'hôte (#191). Chacun de ces renommages est une
rupture ; ils sont groupés pour n'en faire qu'une.
