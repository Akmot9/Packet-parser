# Provenance

Deux captures versées le 2026-07-13 (`6a6b1f6 test: captures de référence
HTTP, Modbus et 4SICS`) sans fichier de provenance ; provenances établies le
2026-10-12 par comparaison d'empreintes (#104).

## `MODBUS-TestDataPart2.pcap`

Fichier `pcaps/openics/MODBUS-TestDataPart2.pcap` du dépôt
**ITI/ICS-Security-Tools** (Information Trust Institute, University of
Illinois), repris à l'octet près : même MD5 que l'original
(`8da217b6bf33d4c090447b2af780b143`), que le dépôt publie aussi sous
`pcaps/ModbusTCP/modbus_test_data_part2.pcap`. SHA-256 de la copie :
`f7cca627fe9b740b5881e8b33b4143b59158240192ecbf5caa727a7dda35d110`. Capture
du 2006-07-21 (166.161.16.230 ↔ 192.168.66.235). La collection
automayt/ICS-pcap range le même fichier sous « digitalbond pcaps » : ce
seraient les données de test Modbus de Digital Bond (projet Quickdraw), qu'ITI
redistribue.

- **Licence** : CC-BY-4.0, texte dans
  [`LICENSES/CC-BY-4.0.txt`](../../LICENSES/CC-BY-4.0.txt). L'attribution est
  obligatoire : citer *ITI/ICS-Security-Tools — ICS PCAPs, developed as a
  community asset* (<https://github.com/ITI/ICS-Security-Tools>). Aucune
  modification.

## `Modbus.pcap`

Identique à l'octet près (SHA-256
`9e055a2d15a8e447be131002137341ae5f8f8b91b64576cd2fdbd854e141373e`, 8 337
octets) au fichier `MODBUS/Modbus/Modbus.pcap` de la collection
[automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) (objet Git LFS,
vérifié le 2026-10-12), que
[EmreEkin/ICS-Pcaps](https://github.com/EmreEkin/ICS-Pcaps) recopie. Capture
du 2008-10-09 : 102 trames Modbus/TCP entre 192.168.110.131 (Wistron) et
192.168.110.138 (Intel).

- La collection automayt n'a pas de licence et ne dit pas d'où vient ce
  fichier : elle crédite en bloc Digital Bond, 4SICS/Netresec, SCADAhacker,
  les samples Wireshark, Shodan, kargs.net et Oak Ridge. Son origine
  première reste **à établir** ; aucune licence ne peut lui être attribuée.
  Il n'est pas dans le dépôt ITI (aucun fichier Modbus de cette taille).
- Redistribué tel quel ; aucun test ne le cite nommément (il compte dans les
  382 trames `ModbusTCP` de l'histogramme golden).
