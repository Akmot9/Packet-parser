# packet_parser

[![CI](https://github.com/Akmot9/Packet-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/Akmot9/Packet-parser/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Akmot9/Packet-parser/graph/badge.svg?token=5YpEN9abhE)](https://codecov.io/gh/Akmot9/Packet-parser)
[![Crates.io](https://img.shields.io/crates/v/packet_parser.svg)](https://crates.io/crates/packet_parser)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![docs.rs](https://img.shields.io/docsrs/packet_parser)](https://docs.rs/packet_parser)
[![Book](https://img.shields.io/badge/book-packet--parser--book-orange)](https://akmot9.github.io/packet-parser-book/)

`packet_parser` est une crate Rust de parsing de paquets reseau. Elle prend une
trame brute, commence a la couche liaison, puis remonte progressivement les
couches internet, transport et application.

Le coeur de l'API est `PacketFlow`: une representation empruntee, zero-copy, du
paquet parse. Les protocoles inconnus ou non supportes au-dessus de la couche
liaison ne font pas echouer tout le parsing: la crate conserve les couches deja
decodees et laisse les couches suivantes a `None` quand c'est necessaire.

![Packet parser overview](images/packet_parser.png)

## Documentation

- **Le livre**, [akmot9.github.io/packet-parser-book](https://akmot9.github.io/packet-parser-book/)
  (en anglais) : la conception de la crate, couche par couche, avec des schemas
  et des exemples testes.
- **La reference de l'API**, [docs.rs/packet_parser](https://docs.rs/packet_parser) :
  chaque type et chaque fonction publics.

## Installation

```toml
[dependencies]
packet_parser = "11.5.0"
```

Pour reproduire les exemples qui decodent de l'hexadecimal:

```toml
[dependencies]
hex = "0.4"
packet_parser = "11.0.0"
```

## Exemple rapide

```rust
use packet_parser::{LinkType, parse};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = hex::decode(
        "feaa81e86d1efeaa818ec864080045500034000000003d06206b36e6700d\
         ac140a0201bbc1087d7f02aa4e2b998e80100081748300000101080a9373\
         c9c207ef14e3",
    )?;

    // Toujours passer le LINKTYPE que la capture declare.
    let flow = parse(LinkType::ETHERNET, &raw)?;

    println!("L2: {}", flow.data_link);

    if let Some(internet) = &flow.internet {
        println!(
            "L3: {} {:?} -> {:?}",
            internet.protocol_name, internet.source, internet.destination
        );
    }

    if let Some(transport) = &flow.transport {
        println!(
            "L4: {:?} {:?} -> {:?}",
            transport.protocol, transport.source_port, transport.destination_port
        );
    }

    if let Some(application) = &flow.application {
        println!("L7: {}", application.application_protocol);
    }

    Ok(())
}
```

## Choisir le LINKTYPE

`parse` est ferme par defaut sur la couche liaison: le LINKTYPE vient de
l'appelant, il n'est jamais devine a partir des octets. Verifiez-le en amont
pour refuser une capture avant d'avoir lu un seul paquet:

```rust
use packet_parser::{LinkType, is_supported, parse};

let link_type = LinkType::ETHERNET;
if !is_supported(link_type) {
    return Err(format!("LINKTYPE non supporte: {}", link_type).into());
}

let flow = parse(link_type, packet_bytes)?;
```

`packet_bytes` doit contenir exactement un paquet, sans en-tete d'enregistrement
PCAP ou PCAPNG. `LinkType` utilise l'espace canonique `LINKTYPE_*` stocke dans
les fichiers. Un adaptateur de capture live doit d'abord normaliser les valeurs
`DLT_*` lorsque leur valeur numerique differe. Pour PCAPNG, le lecteur resout
l'interface referencee par chaque paquet et transmet le LINKTYPE de cette
interface.

### Ne pas utiliser le raccourci Ethernet sur une capture inconnue

`PacketFlow::try_from(&[u8])` et `DataLink::try_from(&[u8])` prennent une simple
tranche d'octets et **presument Ethernet**. Ils sont conserves pour
compatibilite et seront retires dans une prochaine version majeure.

Ils n'echouent pas sur une capture non-Ethernet: ils produisent silencieusement
des donnees fausses. Une trame `LINKTYPE_LINUX_SLL` (ce que donne une capture
sur l'interface `any` sous Linux) voit ses 16 octets d'en-tete cooked relus
comme un en-tete Ethernet: l'appel retourne `Ok` avec des adresses MAC
fabriquees, `internet: None` et `corrupted: None`. Rien ne signale l'erreur, et
une matrice de flux construite dessus se remplit d'adresses qui n'ont jamais
existe sur le cable.

LINKTYPE supportes:

| LINKTYPE | Valeur | Etat du decodeur |
| --- | ---: | --- |
| Loopback BSD (NULL) | 0 | Supporte : quatre octets de famille d'adresses, puis le paquet IP. L'ordre d'octets est celui de la machine de capture, donc le champ est lu dans les deux sens et recoupe avec la version IP. `LINKTYPE_LOOP` (108), son jumeau OpenBSD en ordre reseau, n'est pas traite — aucune capture ne l'atteste |
| Ethernet | 1 | Supporte |
| RAW IP | 101 | Supporte pour IPv4 et IPv6 |
| IEEE 802.11 natif | 105 | Modelise pour les flux internes CAPWAP ; decodeur de capture non disponible |
| Linux SLL v1 | 113 | Supporte |
| Bluetooth H4 avec pseudo-en-tete | 201 | Identifie, explicitement non supporte |
| IPv4 brut | 228 | Supporte |
| IPv6 brut | 229 | Supporte |
| mPacket IEEE 802.3br | 274 | Supporte pour les mPackets express (SMD-E) ; les fragments preemptibles (SMD-S/C) sont refuses avec une erreur nommee, leur reassemblage etant a etat |
| Linux SLL v2 | 276 | Supporte |
| Toute autre valeur | Preservee telle quelle | `ParseError::UnsupportedLinkType` |

Un LINKTYPE non supporte est refuse avant de decoder les octets du paquet. Les
protocoles inconnus des couches superieures conservent le comportement gracieux
`None`/`corrupted` decrit plus haut.

Pour RAW IP, un paquet vide ou un nibble de version different de 4/6 retourne
un `InvalidLinkLayer(LinkLayerError)` structure. Des qu'IPv4 ou IPv6 est
identifie, un header IP invalide ou tronque reste un flux partiel reussi avec
`corrupted: Internet` ; la liaison et sa comptabilite sont conservees.

Linux SLL v1 decode son en-tete cooked de 16 octets en ordre reseau et conserve
le type de paquet, le type materiel ARPHRD brut, la longueur d'adresse declaree,
les octets d'adresse source disponibles et la valeur du protocole. Les valeurs
numeriques inconnues sont preservees ; une adresse plus longue que le slot wire
de huit octets est signalee tronquee plutot que rejetee. Utiliser le
`LinkType::LINUX_SLL` canonique (113) : la valeur 25 affichee par certains
champs Wireshark est un identifiant d'encapsulation WTAP interne.

Linux SLL v2 decode independamment son en-tete de 20 octets et conserve en plus
l'index numerique de l'interface de la machine de capture ainsi que le champ
reserve MBZ. Une valeur reservee non nulle est preservee et signalee par
`reserved_is_zero()` plutot que de perdre un paquet autrement decodable, comme
le fait le dissecteur tolerant de Tshark. Les noms d'interface ne sont pas
resolus, car ils appartiennent a la machine de capture. Utiliser le
`LinkType::LINUX_SLL2` canonique (276) ; l'identifiant d'encapsulation WTAP
interne actuellement affiche par Wireshark pour ce format vaut 210.

Chaque flux parse transporte maintenant un `LinkLayer` generique. Ses
accesseurs communs ne supposent pas Ethernet:

```rust
println!("LINKTYPE={}", flow.data_link.link_type());
println!("suivant={:?}", flow.data_link.network_protocol());

if let Some(ethernet) = flow.data_link.as_ethernet() {
    println!("{} -> {}", ethernet.source_mac, ethernet.destination_mac);
}
```

`network_payload()` retourne le slice L3 emprunte. Les vues propres au format
sont explicites (`as_ethernet()`, `as_raw_ip()`, `as_linux_sll()`,
`as_linux_sll2()`, `as_ieee80211()`), afin que RAW et les deux formats SLL ne
puissent jamais fabriquer silencieusement des champs Ethernet.

## API principale

| Besoin | API |
| --- | --- |
| Verifier la presence d'un decodeur | `is_supported(LinkType)` |
| **Parser un paquet (voie canonique)** | `parse(LinkType, &[u8])` |
| Parser avec des ports declares par l'appelant ("Decode As" : mon FTP tourne sur 2121) | `parse_with(LinkType, &[u8], &ParseConfig::new().decode_as(port, DecodeAsProtocol::..))` |
| Parser Ethernet, raccourci de compatibilite — presume Ethernet, voir plus haut | `PacketFlow::try_from(&[u8])` |
| Parser seulement Ethernet/VLAN — presume Ethernet, voir plus haut | `DataLink::try_from(&[u8])` |
| Parser seulement L3, depuis le protocole annonce par la couche liaison | `Internet::try_from_network_parts(NetworkProtocol, &[u8])` |
| Parser seulement L4, depuis le protocole annonce par l'en-tete IP | `Transport::try_from_parts(Option<TransportProtocol>, &[u8])` |
| Detacher le resultat du buffer d'origine | `flow.to_owned_flow()` → `PacketFlowOwned` |
| Recuperer les flux encapsules | `flow.flatten()` |
| Mesurer un LINKTYPE explicite | `parse_timed(...)` avec la feature `parse_timing` |
| Mesurer Ethernet via l'API de compatibilite | `PacketFlow::try_from_timed(...)` avec la feature `parse_timing` |

`PacketFlow` contient:

```rust
pub struct PacketFlow<'a> {
    pub data_link: LinkLayer<'a>,
    pub internet: Option<Internet<'a>>,
    pub transport: Option<Transport<'a>>,
    pub application: Option<Application>,
    pub inner: Option<Box<PacketFlow<'a>>>,
}
```

Le schema de serialisation 7.0 imbrique la liaison et utilise des tags stables.
Les modeles emprunte et owned de la liaison produisent le meme JSON (les octets
du payload ne sont pas serialises):

```json
{
  "data_link": {
    "link_type": 1,
    "network_protocol": { "kind": "ipv4" },
    "link_kind": "ethernet",
    "link_details": {
      "destination_mac": "00:11:22:33:44:55",
      "source_mac": "66:77:88:99:aa:bb",
      "ethertype": "IPv4"
    }
  }
}
```

## Protocoles

### Liaison

- Ethernet II
- VLAN 802.1Q
- RAW IPv4/IPv6 (`LINKTYPE_RAW`)
- Linux cooked capture v1 (`LINKTYPE_LINUX_SLL`)
- Linux cooked capture v2 (`LINKTYPE_LINUX_SLL2`)
- Adresses MAC et resolution OUI interne
- Representation IEEE 802.11 native pour les flux internes CAPWAP (pas encore
  de decodeur LINKTYPE de premier niveau)

### Internet

- ARP
- IPv4
- IPv6
- Profinet : toute classe de Frame ID RT (donnees cycliques, alarmes, PTCP,
  fragments) est validee ; les messages DCP sont decodes bloc par bloc par
  `ProfinetPacket`
- PTP (IEEE 1588) directement sur Ethernet, EtherType `0x88F7`, decode dans
  `InternetDetails::Ptp`

Pour IPv4 fragmente, la crate ne fait pas de reassemblage IP. Dans ce cas,
`payload_protocol` vaut `None` pour eviter de parser une couche transport
incomplete.

### Transport

- TCP
- UDP
- ICMPv4 (echo request/reply, et les messages d'erreur qui citent le
  datagramme original : destination unreachable, redirect, time exceeded,
  parameter problem). Atteint par le numero de protocole IP 1, jamais par
  probing.
- ICMPv6 (echo request/reply, les messages d'erreur qui citent le paquet
  invoquant, et la decouverte RFC 4861 : router solicitation et advertisement
  — cette derniere avec hop limit, drapeaux M/O, duree de vie du routeur,
  reachable time et retransmit timer — plus neighbor solicitation et
  advertisement avec adresse cible et drapeaux R/S/O). Atteint par le next
  header IPv6 58. La numerotation des types est disjointe de celle d'ICMPv4 —
  128 y est un echo request, 8 n'est pas defini — d'ou deux parseurs separes.

Aucune version d'ICMP ne porte de couche applicative : `payload` reste `None`
et le message decode est expose via `TransportDetails::Icmp` /
`TransportDetails::Icmpv6`.
- Mapping de nombreux numeros de protocoles IP vers `TransportProtocol`

Les protocoles autres que TCP/UDP/ICMP peuvent etre representes par leur enum,
mais ils ne fournissent pas toujours ports et payload applicatif.

### Application

La detection applicative est volontairement best-effort. Les modules de parsing
incluent notamment:

- DNS (mDNS inclus via `DnsPacket::try_from_mdns`)
- TLS
- SNMP
- NTP
- DHCP / DHCPv6
- HTTP
- MQTT
- PostgreSQL
- FTP
- SMTP
- NNTP
- SSH (chaine d'identification seulement : tout ce qui suit l'echange de
  versions est chiffre, donc un parseur stateless etiquette les trames de
  banniere et rien d'autre)
- Modbus TCP
- UMAS (Schneider Electric)
- EtherNet/IP
- OPC UA
- S7Comm
- COTP
- AMS
- GIOP
- SRVLOC
- ASTERIX (donnees de surveillance EUROCONTROL, onze categories : CAT 048
  et 034, plots et messages de service monoradar, CAT 001 et 002 leurs
  equivalents de premiere generation, CAT 008 meteo, CAT 021 ADS-B, CAT 023
  etat des stations sol, CAT 062 pistes systeme, CAT 063 etat des capteurs,
  CAT 065 etat du SDPS, CAT 247 numeros de version). Reconnu par sa seule
  structure — tous les data blocks d'une categorie connue, records decoupes
  exactement selon l'UAP, Random Field Sequencing compris — faute de magic
  et de port IANA
- QUIC
- Bitcoin
- RTPS (OMG DDSI-RTPS 2.x, le protocole filaire de DDS) : en-tete,
  sous-messages decoupes et types (DATA, DATA_FRAG, HEARTBEAT, ACKNACK, GAP,
  INFO_TS, INFO_DST, INFO_SRC, sous-messages de fragments, DDS Security et
  vendeur), identifiants d'entite, numeros de sequence et compteurs ; les
  donnees utilisateur (CDR) et les QoS en ligne restent opaques. Reconnu par
  son magic (`RTPS`, ou `RTPX` chez RTI) et le pavage exact de ses
  sous-messages, sur tout port UDP ; les pings RTI de seize octets
  (`NDDSPING`) sont signales aussi
- DNP3 (IEEE 1815) : trames de liaison aux CRC-16/DNP verifies, en-tete et
  blocs (longueur, bits de controle et fonction, adresses), en-tete de
  transport, en-tete applicatif (controle, code de fonction, indications
  internes) et chaine des en-tetes d'objets (groupe, variation, qualificatif,
  plage ou compte, position des donnees dimensionnees par l'annexe A),
  plusieurs trames par payload. Reconnu a l'aveugle sur TCP et UDP, les CRC
  sont la signature
- IKE (ISAKMP/IKEv1 RFC 2408, IKEv2 RFC 7296) sur UDP 500 et 4500 : en-tete
  de 28 octets (SPI, version, type d'echange nomme, drapeaux, identifiant de
  message, longueur), chaine des payloads de premier niveau avec leurs types
  nommes, octets chiffres gardes tels quels (drapeau E d'IKEv1, payload SK
  d'IKEv2) ; UDP 4500 demultiplexe selon la RFC 3948 (marqueur non-ESP,
  NAT-keepalive, ESP)
- ESP (RFC 4303) : SPI et numero de sequence, natif (protocole IP 50, expose
  en `TransportDetails::Esp`) comme encapsule dans UDP 4500 (`EspPacket`),
  le reste garde en octets chiffres
- DIS (IEEE 1278.1, Distributed Interactive Simulation) : en-tete de PDU
  (versions 1 a 7, les 72 types de la norme nommes, famille, horodatage,
  longueur, PDU Status), corps Entity State, Transmitter et Signal types,
  les autres en octets, plusieurs PDU par datagramme. Reconnu a l'aveugle
  quand les PDU pavent exactement le datagramme ; sur UDP 3000 (ou un port
  declare par Decode As), une longueur declaree fausse est toleree et le
  reste garde en octets de fin
- STANAG 5066 SIS (Subnetwork Interface Sublayer, pile de donnees des
  liaisons radio HF de l'OTAN) sur TCP 5066 : tous les types de S_PDU
  (bind, liaisons dures, disponibilite du sous-reseau, gestion, donnees et
  donnees expediees avec leurs confirmations et rejets), adresses de noeud,
  SAP, types de service, TTL, tailles d'U_PDU ; le premier S_PDU du
  segment, signale quand il deborde sur le suivant, `consumed` pour les
  suivants. Garde par port, autre port par Decode As
- PTP (IEEE 1588) sur UDP 319/320 : PTPv2 decode en entier (en-tete commun,
  corps des dix types de message, TLV listes sans decoder leur valeur), PTPv1
  reconnu par son en-tete. Garde par port : un Delay_Req a exactement la
  forme d'un en-tete SLPv1

Dans `PacketFlow`, la detection de FTP, SMTP et NNTP exige a la fois un payload
valide et leur port de controle en clair (TCP 21, 25/587 et 119
respectivement). Les payloads sur d'autres ports ne recoivent pas ces labels :
leur syntaxe en lignes peut aussi apparaitre dans le corps d'un autre protocole
textuel. Les enregistrements TLS complets sur des ports TLS implicites comme
465, 563 et 990 restent classes TLS. Pour examiner des donnees applicatives
dechiffrees en externe, utilisez directement le parseur detaille du protocole.

`PacketFlow` remonte actuellement un nom de protocole applicatif simple dans
`Application { application_protocol }`. Pour un parsing detaille d'un protocole
precis, utilisez directement le module correspondant dans
`packet_parser::parse::application::protocols`.

## Tunnels

`PacketFlow` peut representer plusieurs niveaux de flux via `inner`.

Les tunnels supportes aujourd'hui:

| Tunnel | Porte par | Interne |
| --- | --- | --- |
| CAPWAP-Data | UDP/5247 | IEEE 802.11 → LLC/SNAP → L3 |
| GRE (v0) | protocole IP 47 | IPv4, IPv6 ou Ethernet |
| IP-in-IP | protocoles IP 4 et 41 | IPv4 / IPv6 nu |
| VXLAN | UDP/4789 | trame Ethernet complete |
| Geneve | UDP/6081 | Ethernet (0x6558) ou IP nue |
| GTP-U | UDP/2152 | IP nue, sans couche 2 |

Les variantes que rien n'atteste sont refusees plutot que devinees : ERSPAN
et GRE version 1, les extensions de flags GBP/GPE de VXLAN, les messages de
controle OAM de Geneve, et — pour GTP-U — GTPv0, GTP' et tout message type
autre que G-PDU.

Les datagrammes externes fragmentes ne sont pas peles : le reassemblage est
a etat, hors perimetre de ce parseur. Un tunnel n'est donc jamais annonce
plus complet que le datagramme qui le porte.

Exemple:

```rust
let flow = PacketFlow::try_from(packet.as_slice())?;

for level in flow.flatten() {
    println!("{:?} -> {:?}", level.internet, level.transport);
}
```

## Features

| Feature | Effet |
| --- | --- |
| `parse_timing` | Fait réellement mesurer chaque couche par `parse_timed` et `PacketFlow::try_from_timed` ; sans elle la même API existe et `ParseTiming` reste à zéro |

La feature `parse_timing` est faite pour les benchmarks. Le chemin normal
`PacketFlow::try_from` ne mesure pas le temps de parsing.

Exemple:

```rust
use packet_parser::{PacketFlow, timing::ParseTiming};

let mut timing = ParseTiming::default();
let flow = PacketFlow::try_from_timed(packet.as_slice(), &mut timing)?;

println!("L2={}ns L3={}ns L4={}ns L7={}ns total={}ns",
    timing.l2_ns,
    timing.l3_ns,
    timing.l4_ns,
    timing.l7_ns,
    timing.total_ns,
);
```

Activation:

```bash
cargo test --features parse_timing
```

## Benchmarks et rapport HTML

Le harnais de benchmark principal est `tools/verbench`. Il compare les versions
publiees de la crate sur crates.io avec la copie locale, puis genere:

- `perf_by_version.json`
- `perf_by_version.html`

Execution complete:

```bash
tools/verbench/run.sh
```

Regenerer seulement le rapport HTML depuis le JSON existant:

```bash
python3 tools/verbench/report.py
```

Le rapport HTML est autonome: il s'ouvre directement dans le navigateur et ne
depend pas de Docker, Postgres, Grafana ou d'un CDN.

```bash
xdg-open perf_by_version.html
```

`tools/verbench` mesure les moyennes `l2_ns`, `l3_ns`, `l4_ns`, `l7_ns` et
`total_ns` sur un paquet de reference, apres warmup. Les chiffres servent a
comparer les tendances entre versions sur une meme machine, pas a publier une
latence absolue universelle.

## Pipeline PCAP optionnel

Le workspace contient aussi `benchmark_db`, un binaire qui parse des PCAP locaux
et ecrit des evenements JSONL avec:

- `run_id`
- `crate_code`
- `pcap`
- index du paquet
- hash du paquet
- duree totale
- timings OSI si `parse_timing` est active

Commande:

```bash
cargo run -p benchmark_db --release
```

Les fichiers sont ecrits dans:

```text
~/.local/share/packet_parser_bench/jsonl/
```

Le pipeline Docker `docker-compose.yml` peut ensuite ingester ces JSONL dans
Postgres et les afficher dans Grafana, mais il est optionnel.

## Exemples

Le dossier `examples/` contient plusieurs points d'entree utiles:

```bash
cargo run --example parse_tcp
cargo run --example parse_hex_dump
cargo run --example pars_quic
cargo run --example parse_pgadm
```

## Tests et qualite

Commandes courantes:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
cargo build --release
```

Pour les binaires qui lisent des PCAP via la crate `pcap`, installez aussi les
dependances systeme de libpcap. Sur Debian/Ubuntu:

```bash
sudo apt-get install libpcap-dev
```

## Limites connues

- Pas de reassemblage TCP.
- Pas de reassemblage IP.
- La detection applicative est heuristique et best-effort.
- Le chemin `parse_timing` est dedie aux mesures et ne doit pas etre confondu
  avec le chemin de parsing standard.
- Le parsing timé ne mesure pas encore recursivement les flux `inner` issus des
  tunnels.

## Licence

Distribue sous licence MIT. Voir [LICENSE.md](LICENSE.md).
