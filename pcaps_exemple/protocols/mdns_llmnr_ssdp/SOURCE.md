# Provenance

Les captures mDNS sont des extraits du sample public Wireshark
[`mDNS1.zip`](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mDNS1.zip),
archive de captures Apple Rendezvous au format Microsoft Network Monitor.

Extraction effectuee le 2026-08-03 avec `editcap` :

- `mdns_query_response.pcapng` : trames originales 21, 36 et 40 de
  `mDNS3.cap` (question, bit QU et reponse avec cache-flush) ;
- `mdns_announcement.pcapng` : trame originale 1 de `More-mDNS.cap`
  (annonce sans question).

Seules les trames mDNS necessaires aux golden tests sont conservees. Les
adresses et noms du sample sont des valeurs de demonstration ; aucune autre
anonymisation n'a ete appliquee.

## Licence

Samples du wiki Wireshark : GNU GPL sans numéro de version (<https://wiki.wireshark.org/License> ; toute version publiée par la FSF peut s'appliquer, GPL v2 §9), texte dans
[`LICENSES/GPL-2.0.txt`](../../LICENSES/GPL-2.0.txt). Les modifications que la
licence oblige à signaler sont celles décrites ci-dessus : extraction et
troncature du 2026-08-03 (#104).
