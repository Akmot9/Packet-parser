# Provenance

Les deux captures sont des extraits des samples publics Wireshark
[`FTPv6-1.cap` et `FTPv6-2.cap`](https://wiki.wireshark.org/SampleCaptures),
decrits comme du trafic FTP sur IPv6.

Extraction effectuee le 2026-08-03 avec `editcap` :

- `ftp_ipv6_lowercase.pcapng` : trames originales 329 (`opts`), 385
  (`syst`) et 442 (`site`) de `FTPv6-1.cap` ;
- `ftp_ipv6_extensions.pcapng` : trames originales 142 (`noop`) et 280
  (`LPRT`) de `FTPv6-2.cap`.

Les captures ont ete tronquees aux seules commandes de controle utiles aux
tests. Les trames `USER`/`PASS` et les transferts de donnees ne sont pas
conserves. Aucune autre anonymisation n'a ete appliquee au sample public.
