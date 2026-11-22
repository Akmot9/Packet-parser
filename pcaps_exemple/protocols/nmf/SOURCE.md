# Provenance

Une capture **.NET Message Framing** ([MC-NMF], le tramage de WCF `net.tcp`)
versée le 2026-11-22 pour les issues #351 et #352. Aucune capture NMF
publique n'a été trouvée : le tracker Wireshark n'en a que des fichiers de
fuzz.

## `terrain_nmf_censure.pcap` — capture du mainteneur, censurée

32 trames extraites d'une capture de terrain du mainteneur, puis censurées
par `tools/censor_capture.py --proto nmf --check`. L'original n'est pas
publié.

| Fichier | Trames | Segments à charge | Contenu | SHA-256 |
|---|---|---|---|---|
| `terrain_nmf_censure.pcap` | 32 | 23 | une session complète (préambule, accusé, quatre enveloppes à taille, fin) et le milieu d'une autre : sept segments de suite, la première enveloppe d'un message de 50 253 octets, puis huit segments de suite | `e85117c63e204cfeccb9fdef7bc888f1729e88fd2eeafce23397d89964dbb7c3` |

### Ce que la censure a réécrit

- horodatages : la première trame part de l'époque 0, les écarts sont
  gardés ;
- adresses MAC : `02:00:00:00:00:NN` ;
- identifiant de VLAN : 1 ;
- adresses IPv4 : `192.0.2.N` (TEST-NET-1, RFC 5737) ;
- ports : 50000 à 50003 (les services écoutent sur 50001 et 50002) ;
- sommes de contrôle IPv4 et TCP : recalculées, justes ;
- URI de l'enregistrement Via : `net.tcp://host/xxx…`, de même longueur ;
- chaînes de la table [MC-NBFSE] : des `x`, de même longueur ;
- corps des enveloppes et segments de suite : des octets nuls.

### Ce qui est d'origine

Les en-têtes Ethernet, IPv4 et TCP hors des champs ci-dessus (numéros de
séquence, fenêtres, drapeaux, options, identifiants IP, TTL), le découpage
en segments, les types d'enregistrement, les tailles, le mode, l'encodage
connu, les longueurs de la table de chaînes et les six octets `s:Envelope`
qui ouvrent chaque message.

## Ces trames sont-elles réelles ?

Oui pour tout ce que le décodeur lit : le tramage vient d'une pile WCF en
service, pas d'octets écrits à la main. Non pour le contenu des messages,
qui n'existe plus. Un test qui porterait sur le XML binaire d'un message
ne peut pas s'appuyer sur ce fichier.

tshark 4.6.9, les ports des services déclarés
(`-d tcp.port==50001,mc-nmf -d tcp.port==50002,mc-nmf`), voit les mêmes
types d'enregistrement, tailles, mode, encodage et longueur de Via avant et
après censure, et des sommes de contrôle justes.

## Oracle

`tools/nmf_oracle.sh` écrit `tests/data/nmf_tshark_oracle.tsv` : une ligne
par segment à charge. Le dissecteur de tshark ne réassemble pas : il lit les
quinze segments de suite comme des enregistrements, ce que
`tests/nmf_golden.rs` note et ne suit pas.

## Licence

Capture du mainteneur : sous la licence MIT du dépôt (voir
`../../LICENSES/README.md`).
