# Roadmap packet_parser

Etat au 2026-08-04 : la 10.0.0 est publiee (decodage COTP complet, enveloppe
S7Comm stricte, nettoyage de l'API morte). Elle ouvre une **fenetre de
stabilite** : tout ce qui suit est realisable sans nouvelle version majeure,
et l'objectif est de tenir 6 a 12 mois sans rupture d'API.

Chaque ajout suit la methode canonique (`METHODE_AJOUT_PROTOCOLE.md`) :
extract_* par champ dans checks, TryFrom lineaire, golden tests sur trames
reelles, choix documente de la voie de detection (probing aveugle si la
signature est forte, garde de port sinon).

## 1. Chantiers ouverts (issues GitHub)

Les epics et leurs sous-issues sont sur GitHub, chacune avec fichiers
concernes et critere d'acceptation.

| Epic | Sujet | Etat |
|---|---|---|
| #38 | Nettoyage d'API pour la 10.0.0 | ✅ clos (livre en 10.0.0) |
| #46 | Durcissements de validation (http, quic, dhcp, srvloc) | ouvert |
| #51 | Completer les parseurs (dispatch GIOP, body SLPv2, Retry QUIC, detection TLS #55) | ouvert |
| #56 | Golden tests manquants (ethernet_ip, giop, quic) | ouvert |
| #60 | Zero-copy integral (rdata DNS, Vec postgresql/opcua/http) | ouvert |
| #64 | Detection hors port standard : API « Decode As » + verbes non-ambigus FTP/SMTP/NNTP | ouvert |
| #67 | Nouveaux protocoles : LLMNR (#68) et SSDP (#69) | ouvert |
| #70 | Generaliser la regression tshark (modbus, dns, tls) | ouvert |

Priorites au sein des chantiers : #55 (le parseur TLS existe mais n'est
cable dans aucune voie de detection) et #56 (dette vis-a-vis de la regle
« trames reelles obligatoires »).

## 2. Nouveaux protocoles proposes

Criteres de priorisation : coherence avec le positionnement ICS/OT et
analyse securite, force de la signature wire, disponibilite des captures,
synergie avec le code existant.

### Tier 1 — les evidences (captures deja dans le repo ou dossier prepare)

| Protocole | Detection | Notes |
|---|---|---|
| ICMP / ICMPv6 detaille | protocole IP 1/58, pas de probing | Captures deja presentes (`pcaps_exemple/protocols/icmp/`). Trou fonctionnel : reconnu au transport mais jamais decode (echo, unreachable, TTL exceeded, neighbor discovery). |
| UMAS (Schneider Electric) | s'empile sur Modbus TCP (fonction 90), port 502 | Grosse valeur ICS. Meme modele d'empilement que S7comm sur COTP ; le parseur Modbus existe deja. Dossier `protocols/umas/` prepare. |
| NetBIOS-NS / Datagram | UDP 137/138, format proche DNS | Dossier `protocols/netbios/` prepare ; omniprésent dans les captures Windows (deja visible dans mDNS3.cap et smtp.pcap). |
| RADIUS | UDP 1812/1813, en-tete code+id+length+authenticator | Capture deja presente (pcap CAPWAP « + radius a partir de la ligne 33003 »). Coherent avec le travail CAPWAP. |
| OpenVPN | garde de port (1194) + opcode/session id | Dossier `protocols/openvpn/` prepare. |
| STP (BPDU) | couche L2 (LLC DSAP 0x42), pas la chaine applicative | Dossier `protocols/stp/` prepare ; se branche cote data_link comme Profinet. |

### Tier 2 — cœur de cible ICS/OT (le differenciateur de la crate)

| Protocole | Detection | Notes |
|---|---|---|
| DNP3 | TCP/UDP 20000 ; octets de depart 0x05 0x64 + CRC par bloc → **probing aveugle possible** | LE protocole du secteur electrique nord-americain. Meme doctrine que S7comm : signature d'enveloppe assez forte pour se passer du port. |
| IEC 60870-5-104 | TCP 2404 ; start 0x68 + longueur APDU → garde de port | L'equivalent europeen de DNP3. |
| BACnet/IP | UDP 47808 ; BVLC 0x81 + fonction + longueur exacte | Building automation. |
| GOOSE / Sampled Values (IEC 61850) | EtherTypes L2 0x88B8 / 0x88BA | Se branche dans la couche internet a cote de Profinet, pas dans la chaine applicative. |

Captures publiques disponibles (Wireshark wiki, corpus Netresec) ; verifier
d'abord si `4SICS-GeekLounge-151020.pcap` contient deja du DNP3/IEC104.

### Tier 3 — indispensables analyse securite IT

| Protocole | Detection | Notes |
|---|---|---|
| SSH | banniere litterale `SSH-2.0-...` → probing aveugle trivial | Le meilleur ratio valeur/effort de la liste ; expose la version serveur. |
| SMB2/3 | magic 0xFE 'S' 'M' 'B' → signature forte | Incontournable pour l'analyse d'incidents Windows. |
| RDP | TPKT + COTP (X.224 CR, cookie mstshash), port 3389 | Reutilisation directe du chantier COTP de la 10.0.0. |
| DTLS | decalque du parseur TLS + epoch/sequence, UDP | Utile pour WebRTC et CAPWAP-DTLS (deja croise dans les captures du repo). |
| WireGuard | UDP ; type 1-4 + 3 octets reserves a zero | Signature correcte, tres demande. |
| SIP | UDP/TCP 5060, texte a la HTTP | Reutilise les briques request-line/headers de http. |

## 3. Ordre recommande

1. **ICMP** — captures pretes, trou fonctionnel.
2. **UMAS** — differenciateur ICS, s'appuie sur Modbus.
3. **SSH** — ratio valeur/effort imbattable.
4. **DNP3** — ouvre le secteur energie.
5. **RDP** — rentabilise TPKT/COTP.
6. RADIUS, NetBIOS, LLMNR (#68), SSDP (#69) au fil de l'eau.
7. Tier 2 restant (IEC 104, BACnet, GOOSE/SV), puis Tier 3 restant.

En parallele des protocoles : solder #55 (detection TLS) et #56 (golden
tests manquants), qui sont de la dette plus que de la feature.

## 4. Regles de la fenetre de stabilite

- Aucune rupture d'API sans necessite majeure ; les nouveaux protocoles
  sont additifs (nouveaux modules, nouveaux variants d'enum non_exhaustive).
- Tout nouveau parseur arrive complet : errors + checks + parse + cablage
  detection + golden tests sur trames reelles + entree CHANGELOG.
- Les protocoles a grande surface (DNP3, SMB2) recoivent une cible de fuzz
  et, si des captures riches existent, une regression tshark a la
  s7comm_regression.
- L'integration aval (Sonar_desktop_app) se fait par version mineure :
  la procedure est documentee et rodee (sonar-flows-core, vendor,
  cargo-vet, snapshots).
