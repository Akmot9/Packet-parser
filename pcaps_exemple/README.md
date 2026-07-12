# pcaps_exemple — captures de référence pour les golden tests

Ce dossier accueille les **captures réelles** (pcap/pcapng) qui servent de
source aux golden tests de la crate. Règle du projet : **aucun test de
référence sur des octets fabriqués à la main** — uniquement des trames
réellement capturées sur un réseau.

## Conventions

- Un sous-dossier par protocole ou tunnel ; y déposer un ou plusieurs
  `*.pcap` / `*.pcapng`.
- À côté de chaque capture, noter la **provenance** dans un `SOURCE.md` :
  d'où vient la capture (équipement, environnement, ou URL du sample public),
  la date, et si elle a été anonymisée/tronquée.
- Pas de capture contenant des données sensibles (credentials, IP publiques
  internes, payloads privés) : anonymiser avant dépôt si besoin.
- Pour écrire le golden test : décoder la trame en amont (Wireshark) pour
  figer les offsets et valeurs attendues, puis embarquer le **hex complet
  depuis l'en-tête Ethernet** dans le test, comme pour CAPWAP.

## Attendu par dossier

### `tunnels/` (issue #15 — un test de référence par tunnel = obligatoire)

| Dossier | Attendu | Points à couvrir |
|---|---|---|
| `vxlan/` | Trafic UDP 4789 | interne = Ethernet ; VNI visible |
| `gtp_u/` | Trafic UDP 2152 | message type 255 (G-PDU) ; interne = IP sans L2 ; si possible variantes flags E/S/PN |
| `geneve/` | Trafic UDP 6081 | avec et sans options ; protocol type Ethernet (0x6558) et/ou IP |
| `gre/` | IP proto 47 | interne IP (0x0800/0x86DD) et si possible interne Ethernet (0x6558, NVGRE/gretap) ; variantes bits C/K/S |
| `ipip/` | IP proto 4 (et 41 si possible) | interne = IP directe |
| `capwap/` | UDP 5247 | déjà couvert par 2 golden tests (ToDS/FromDS) ; capture ici pour archivage/variantes |

### `protocols/` (issues ouvertes + protocoles déjà supportés)

| Dossier | Issue | Attendu |
|---|---|---|
| `dns/` | #2 | requêtes/réponses DNS classiques (port 53) |
| `mdns_llmnr_ssdp/` | #2 | mDNS (5353), LLMNR (5355), SSDP (1900) pour lever la confusion avec DNS |
| `netbios/` | #8 | NBNS (137), Datagram (138), Session (139) |
| `openvpn/` | #5 | handshake OpenVPN UDP et/ou TCP |
| `stp/` | #4 | BPDU STP, RSTP, MSTP |
| `s7comm/` | #11 | trafic S7comm v2 **et** v3 pour les distinguer |
| `umas/` | #10 | trafic UMAS (Schneider, sur Modbus/502) |
| `ntp/` | — | existant : `integration_test/pcap/ntp/ntp.pcap` (à migrer ici) |
| `tls/` | — | ✅ `tls12-dsb.pcapng` (sample Wireshark, TLS 1.2 + secrets) et `dump.pcapng` (loopback 4430-4433) — voir `SOURCE.md` |

## Utilisation dans les tests

Les golden tests n'embarquent pas le pcap : ils embarquent le hex de la
trame extraite du pcap, avec un commentaire pointant vers le fichier source
(`pcaps_exemple/<dossier>/<fichier>.pcap`, n° de trame). Le pcap reste ici
comme preuve et pour ré-extraire d'autres variantes.
