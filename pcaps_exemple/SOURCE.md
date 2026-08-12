# Provenance — captures à la racine

Les captures rangées directement dans `pcaps_exemple/` (hors `protocols/`)
précèdent la convention « un sous-dossier par protocole ». Ce fichier comble
leur provenance manquante.

## sll.pcap

- Capture locale de Cyprien, **2026-07-14 15:07 (+0200)**, versionnée le jour
  même par `bd03272 test: golden tests SLL/SLL2 sur captures réelles`.
- Encapsulation **Linux cooked-mode capture v1** (LINKTYPE_LINUX_SLL, 113) —
  capture sur l'interface `any` d'un hôte Linux.
- 2 702 paquets : navigation web ordinaire (TCP/TLS vers plusieurs hôtes,
  résolution DNS) et **une session QUIC v1 sur IPv6** vers un serveur Google
  (`2a00:1450:4006:818::200a:443`), trames 1712 à ~1780.
- Sert de source aux golden tests SLL (`tests/public_parse_api.rs`) et QUIC
  (`tests/quic_golden.rs`, issue #59) : trame 1716 Initial, 1730 Handshake,
  1731 Short header.

## capture_sll2.pcap

- Capture locale de Cyprien, **2026-07-14 15:24 (+0200)**, même commit.
- Encapsulation **Linux cooked-mode capture v2** (LINKTYPE_LINUX_SLL2, 276).
- 779 paquets, même profil : TCP/TLS, DNS, et 32 trames QUIC.
- Sert de source aux golden tests SLL2.

## À compléter par Cyprien

- Quel hôte et quelle interface (`tcpdump -i any` ?), et quel navigateur a
  généré le trafic QUIC — utile pour savoir quelle implémentation QUIC est
  figée dans les goldens.
- **Point de confidentialité** : ces deux captures contiennent l'adresse IPv6
  globale réelle du client (préfixe `2001:8613:fc79:b00b::/64`) et son
  historique de navigation en clair au niveau DNS. Elles ne sont pas
  anonymisées, contrairement à ce que demande le README de ce dossier. À
  arbitrer : anonymiser et regénérer les fixtures, ou assumer le dépôt en
  l'état.
