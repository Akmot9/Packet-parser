# Provenance

Trois captures d'**IKE** et d'**ESP**, versées le 2026-10-08 pour l'issue
#124 (épopée #125, rapport `docs/protocoles-defense.md`). Aucune n'est
modifiée : ni anonymisée, ni tronquée.

Contenu vérifié avec tshark 4.6.6 (`-Y isakmp`, `-Y esp`) : 535 trames IKE
et 323 trames ESP, dont 315 encapsulées dans UDP 4500 (NAT-T).

| Fichier | Trames | Contenu | Origine | SHA-256 |
|---|---|---|---|---|
| `attachment_ikev1_main_mode.pcap` | 12 | IKEv1 main mode, UDP 500 | wiki Wireshark | `5c75e96c60b65a4bf5bb56736eba98251ca69a6a0543c413d3d06b18e9c77b74` |
| `ikev2_s2s_ipsec_vpn_aes_gcm.pcapng` | 12 | IKEv2 (4) puis ESP natif (8) | wiki Wireshark | `7802a8edc23470f698094263479d6f2cd1672ce71a404a604ca741a8a9994615` |
| `ipsec_isakmp_esp.pcap` | 834 | IKE sur UDP 500 (279), NAT-T sur UDP 4500 : IKE (240) et ESP (315) | corpus de tests nDPI | `7160b8863845f302a02e480394afb442742cafb9315bd225677ffb3c2e2016d6` |

## Détail

- **`attachment_ikev1_main_mode.pcap`** — échange main mode entre deux
  machines virtuelles VMware (`10.1.61.155` ↔ `10.1.61.156`), le
  2020-02-11. URL
  `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/attachment_ikev1_main_mode.pcap`.
- **`ikev2_s2s_ipsec_vpn_aes_gcm.pcapng`** — VPN site à site entre
  `10.0.0.1` et `10.0.0.2`, le 2026-06-17 ; l'échange IKEv2 négocie
  AES-GCM (ICV de 16 octets). Les adresses
  MAC `50:00:00:01:00:01` et `50:00:00:02:00:01` ont la forme de celles
  qu'attribue un émulateur de réseau (EVE-NG) : deux routeurs émulés, donc un
  logiciel réel en labo. URL
  `https://wiki.wireshark.org/uploads/c45aa4606b860d707db92e180c147001/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng`.
- **`ipsec_isakmp_esp.pcap`** — un poste (`192.168.2.100`, carte réseau
  Belkin) derrière une box Sercomm, face à des passerelles publiques
  (`109.237.187.x`), avec la traversée de NAT. Commit nDPI épinglé
  `6ac6e1ec2547d23e4f1b60c4f8a81698dff5895f`, chemin
  `tests/cfgs/default/pcap/ipsec_isakmp_esp.pcap`. **Horodatages retouchés** :
  ils partent du 2000-01-01 et ne sont pas monotones, ce qui trahit une
  fusion de captures recalées. Adresses, TTL (63, 247) et matériels (Sercomm,
  Belkin) sont, eux, ceux d'un trafic réel. tshark signale deux checksums
  faux.

`The-Ultimate-PCAP.pcapng`, à la racine de `pcaps_exemple/`, porte aussi
1 600 trames ESP et 719 ISAKMP ; il n'est pas parcouru par les tests de
corpus.

## Licences

- captures de la wiki Wireshark : licence de la wiki (GNU GPL v2+, en pied de
  page de <https://wiki.wireshark.org>) ;
- `ipsec_isakmp_esp.pcap` : LGPL-3.0, licence du dépôt nDPI.

Aucun de ces fichiers n'entre dans le paquet publié sur crates.io. Le texte
des licences n'accompagne pas encore les captures : voir #104.
