# Provenance

Captures EtherNet/IP publiques vendues le 2026-08-20 (issue #57) depuis le
dépôt **ITI/ICS-Security-Tools** (Information Trust Institute, University of
Illinois), dossier `pcaps/EthernetIP/` :

- <https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/EthernetIP/enip_test.pcap>
- <https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/EthernetIP/cip-eth-set-2.pcap>
- <https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/EthernetIP/cip_unlock_cpu.pcap>

**Licence** : CC-BY-4.0 (`LICENSE.md` à la racine du dépôt source,
SPDX `CC-BY-4.0` confirmé par l'API GitHub). L'attribution est obligatoire :
toute redistribution de ces fichiers doit citer *ITI/ICS-Security-Tools —
ICS PCAPs, developed as a community asset*
(<https://github.com/ITI/ICS-Security-Tools>).

**Anonymisation** : fichiers repris à l'octet près, sans modification. Ils ne
contiennent que des adresses privées (10.1.1.0/24, 192.168.10.0/24) — le
dépôt source les publie déjà comme samples communautaires.

Le même dossier source propose `EthernetIP-CIP.pcap` (~2 Mo, 10 880 trames) :
volontairement non vendu, il ferait exploser les oracles de comptage qui
balayent `protocols/` (`tests/golden_pcaps.rs`, `tests/s7comm_regression.rs`)
pour une couverture identique (uniquement des commandes 0x6F/0x70). Aucune
des captures du dossier source ne contient de RegisterSession (0x65) : le
corpus réel couvre ListIdentity, SendRRData et SendUnitData.

| Fichier | Contenu |
|---|---|
| `enip_test.pcap` | 11 trames : scan d'un module 1756-ENBT/A — handshakes TCP vers 44818 puis **ListIdentity** requête (trame 6) et réponse (trame 7) — **source des golden tests** |
| `cip-eth-set-2.pcap` | 1 trame : réponse **SendRRData** (CPF Null Address + Unconnected Data, réponse CIP Set Attribute Single succès) — **source des golden tests** |
| `cip_unlock_cpu.pcap` | 1 trame : requête **SendUnitData** (CPF Connected Address + Connected Data, service CIP 0x4C sur classe 0x8E) — **source des golden tests** |
