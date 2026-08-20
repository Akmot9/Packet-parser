# Provenance

## OpenVPN_UDP_tls-auth.pcapng

- Sample public de la wiki Wireshark, page OpenVPN
  (<https://wiki.wireshark.org/OpenVPN>), fichier
  <https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/OpenVPN_UDP_tls-auth.pcapng>.
- Téléchargé le 2026-08-20, non modifié (ni anonymisé ni tronqué).
- Session OpenVPN sur UDP 1194 entre 192.168.56.103:33198 et
  192.168.56.102:1194 (adresses privées de lab), capturée en janvier 2013,
  440 paquets, tous OpenVPN.
- Mode `tls-auth` : les paquets de contrôle portent un HMAC SHA-1 (20 octets),
  un replay packet-id et un net-time entre la session ID et l'ack array.
- Opcodes présents : P_CONTROL_HARD_RESET_CLIENT_V2 (0x38, trame 1),
  P_CONTROL_HARD_RESET_SERVER_V2 (0x40, trame 2), P_CONTROL_V1 (0x20),
  P_ACK_V1 (0x28), P_DATA_V1 (0x30, première : trame 365).

## OpenVPN_TCP_tls-auth.pcapng

- Même origine (wiki Wireshark, page OpenVPN), fichier
  <https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/OpenVPN_TCP_tls-auth.pcapng>.
- Téléchargé le 2026-08-20, non modifié.
- Même session type sur TCP 1194 (192.168.56.103:51089 ->
  192.168.56.102:1194), 438 paquets, dont 327 segments portant de l'OpenVPN.
- Chaque message OpenVPN est préfixé de sa longueur sur u16 big-endian ;
  certains segments coalisent plusieurs messages (ex. trame 10 : trois
  P_CONTROL_V1).

## Licence

Les captures de la wiki Wireshark sont publiées sous la licence de la wiki
(GNU GPL v2+, comme indiqué en pied de page de <https://wiki.wireshark.org>) ;
elles sont réutilisées ici comme données de test avec citation de la source.
