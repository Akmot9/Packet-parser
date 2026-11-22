# Provenance

Une capture **RTCP** (RFC 3550 §6) versée le 2026-11-22 pour l'issue #354.
Le dépôt n'avait que douze datagrammes RTCP réels, dans
`../sip/wireshark_aaa.pcap` (un SR + SDES + BYE) et `../ntp/ndpi_line.pcap`
(onze messages de retour seuls) ; aucun Receiver Report.

## `terrain_rtcp_censure.pcap` — capture du mainteneur, censurée

40 datagrammes extraits d'une capture de terrain du mainteneur, puis
censurés par `tools/censor_capture.py --proto rtcp --check`. L'original
n'est pas publié.

| Fichier | Trames | Contenu | SHA-256 |
|---|---|---|---|
| `terrain_rtcp_censure.pcap` | 40 | quatre flux entre trois équipements : 20 Sender Report + SDES (un bloc de rapport, un CNAME vide) et 20 Receiver Report + SDES (un bloc de rapport ; CNAME, TOOL et NOTE) | `b45642345194b739bae6f8fb018547fa11dffc873a4301633e40acf53441d1c8` |

### Ce que la censure a réécrit

- horodatages de capture : la première trame part de l'époque 0, les écarts
  sont gardés ;
- adresses MAC : `02:00:00:00:00:NN` ;
- adresses IPv4 : `192.0.2.N` (TEST-NET-1, RFC 5737) ;
- ports : 50000 à 50002 ;
- sommes de contrôle IPv4 et UDP : recalculées, justes ;
- horodatage NTP des Sender Report et champ LSR des blocs de rapport : nuls ;
- texte des items SDES : des `x`, de même longueur.

### Ce qui est d'origine

Les en-têtes Ethernet, IPv4 et UDP hors des champs ci-dessus, et tout le
reste du RTCP : types, compteurs, longueurs, SSRC, horodatage RTP, compteurs
de paquets et d'octets, fraction et cumul de pertes, plus haut numéro de
séquence, gigue, DLSR, types et longueurs des items SDES.

## Ces trames sont-elles réelles ?

Oui pour tout ce que le décodeur lit, à l'horodatage NTP près, qui vaut
zéro. Un test qui porterait sur l'heure d'un Sender Report ou sur le texte
d'un item SDES ne peut pas s'appuyer sur ce fichier ; `wireshark_aaa.pcap`
en garde un exemple intact.

tshark 4.6.9, les ports déclarés (`-d udp.port==5000N,rtcp`), voit les mêmes
types, longueurs, SSRC, compteurs, gigue, pertes et items SDES avant et
après censure, et des sommes de contrôle justes.

## Oracle

`tools/rtcp_oracle.sh` écrit `tests/data/rtcp_tshark_oracle.tsv` : une ligne
par datagramme RTCP de cette capture et des deux autres.
`tests/rtcp_golden.rs` y compare la crate.

## Licence

Capture du mainteneur : sous la licence MIT du dépôt (voir
`../../LICENSES/README.md`).
