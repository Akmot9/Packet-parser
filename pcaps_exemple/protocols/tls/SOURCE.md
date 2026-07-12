# Provenance

## tls12-dsb.pcapng

- Sample public de la suite de tests Wireshark (« TLS 1.2 with decryption
  secrets block »).
- Session TLS 1.2 réelle vers `example.com` (93.184.216.34:443), 17 paquets,
  client 10.9.0.2.
- Contient un Decryption Secrets Block pcapng (`CLIENT_RANDOM …`) permettant
  de déchiffrer la session dans Wireshark — utile pour asserter le contenu
  applicatif attendu.

## dump.pcapng

- Capture locale de Cyprien (2026-07-10), loopback.
- 1095 paquets TCP/TLS vers des serveurs de test sur les ports 4430 à 4433
  (probablement plusieurs versions/configurations TLS, une par port).
- Provenance exacte à compléter par Cyprien : quel outil/serveur écoutait sur
  4430-4433, et quelles versions TLS par port.
