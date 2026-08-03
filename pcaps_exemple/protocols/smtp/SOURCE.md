# Provenance

`smtp_control.pcapng` est un extrait du sample public Wireshark
[`smtp.pcap`](https://wiki.wireshark.org/SampleCaptures), decrit comme un
exemple SMTP simple.

Extraction effectuee le 2026-08-03 avec `editcap`. Le fichier conserve les
trames originales 6, 7, 9, 17, 20 et 21 : banniere, `EHLO`, reponses de
capacites/controle, `DATA` et invitation `354`.

La capture complete contenait une authentification et un message MIME. Elle a
ete tronquee : aucune trame d'identifiant, de mot de passe, d'adresse de
messagerie ou de corps de message n'est conservee. Aucune autre anonymisation
n'a ete appliquee aux trames publiques retenues.
