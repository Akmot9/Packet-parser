# Provenance

Du **Java RMI** (JRMP, *Java RMI Specification*, chapitre 10) entre deux
JVM OpenJDK 11.0.33 sur la boucle locale, versé le 2026-11-17 (#313) :
capture du mainteneur, produite pour le corpus.

## `jdk11-loopback.pcap` — capture du mainteneur

Capture Ethernet de l'interface `lo` (adresses MAC nulles, `127.0.0.1` des
deux côtés), 20,4 s, 394 trames, 11 connexions TCP. Elle se reproduit avec
`tools/java_rmi_capture.sh`, qui compile `tools/java_rmi_capture/JrmpCapture.java`,
lance les deux JVM et capture les ports 1099, 50050 et 50051 avec dumpcap.
Les identifiants tirés au hasard par les JVM (UID, numéros d'objet, ports
éphémères) changent d'une exécution à l'autre : les tests citent les trames
de ce fichier-ci.

- **Serveur** : un registre sur TCP 1099, un objet `Station` exporté sur
  TCP 50050, un connecteur JMX sur TCP 50051 (`service:jmx:rmi://127.0.0.1:50051/jndi/rmi://127.0.0.1:1099/jmxrmi`)
  devant un MBean `capture:type=Counter` qui émet une notification à chaque
  changement de valeur. Bail DGC de 4 s (`java.rmi.dgc.leaseValue`), pour
  que le client renouvelle pendant la capture.
- **Client** : `list` et `lookup` du registre ; `hello`, `add`, `samples`,
  et `fail`, qui lève une exception ; une pause, puis un appel sur la
  connexion réutilisée, que le client sonde d'abord par un Ping ; une
  session JMX (attributs, notifications, opération) ; enfin la libération
  des références, qui produit les `DGC.clean`.
- **Deux connexions écrites à la main** par le mode `raw` du programme, la
  réponse étant celle du registre du JDK : un appel `list()` en
  SingleOpProtocol, en-tête et appel dans un seul segment (trame 319,
  réponse trame 321), et un en-tête au protocole inconnu `0x4e`
  (trame 329), que le registre refuse par ProtocolNotSupported (trame 331).

Les 236 segments à charge se répartissent ainsi, selon tshark 4.6.9 par
Decode As sur 50050 et 50051 : 60 Return (dont un exceptionnel, trame 69),
59 Call, 42 Ping, 42 PingAck, 10 en-têtes de flux (9 StreamProtocol, un
SingleOpProtocol suivi de son appel), 9 ProtocolAck, 9 EndpointIdentifier
du client (« Continuation » pour tshark : ce message n'a pas d'octet de
type), 3 DgcAck, un en-tête au protocole inconnu et un
ProtocolNotSupported.

**Aucune donnée de la machine** : `java.rmi.server.hostname=127.0.0.1`
fixe l'adresse annoncée dans les références distantes et les
EndpointIdentifier. Les charges ont été relues : on n'y trouve que
`127.0.0.1`, les noms de classes du JDK et du programme, les chaînes du
programme (`station`, `bonjour capture`, `echec volontaire de la capture`,
`capture:type=Counter`) et la version du JDK (`11.0.33`), dans les traces
de pile de l'exception. Aucun nom d'hôte, d'utilisateur ni chemin.
Conversion pcapng → pcap par `editcap -F pcap` : les métadonnées pcapng
(système, interface) disparaissent.

SHA-256 du fichier déposé :
`b4ff90d3a258090fe925c546366b745f07707fd60447f45f77c7e5d76cd00254`.

## Oracle

tshark ne dissèque RMI que sur TCP 1099 : `tools/java_rmi_oracle.sh` lui
déclare 50050 et 50051 par `-d tcp.port==…,rmi` et écrit, par segment à
charge, le type de message et les champs de l'en-tête de flux et du
ProtocolAck dans `tests/data/java_rmi_tshark_oracle.tsv`.
`tests/java_rmi_golden.rs` y compare la crate, puis vérifie ce que tshark
ne décode pas : les appels du port 1099 visent le registre (ObjID 0, hash
d'interface `0x44154dc9d4e63bdf`, opérations bind, list, lookup et unbind),
ceux du DGC l'ObjID 2 (hash `0xf6b6898d8bf28643`, dirty et clean), et
l'UID de chaque DgcAck est celui d'un Return reçu avant.

## Licence

Capture du mainteneur : sous la licence MIT du dépôt (voir
`pcaps_exemple/LICENSES/README.md`). `pcaps_exemple/` n'entre pas dans le
paquet publié sur crates.io.
