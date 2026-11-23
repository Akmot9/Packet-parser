#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/syslog_golden.rs (#374).
#
# Une ligne par datagramme UDP ou segment TCP ou tshark lit une priorite
# syslog, dans pcaps_exemple/The-Ultimate-PCAP.pcapng et dans les captures
# de pcaps_exemple/protocols/syslog/. Reglages :
# - reassemblage TCP coupe, analyse des numeros de sequence coupee : chaque
#   segment est lu seul, retransmissions comprises, comme par la crate ;
# - tshark ne lit syslog d'office que sur UDP 514 (il prend TCP 514 pour du
#   RSH) : les ports TCP 514 et 601, et le port hors standard de
#   ndpi_syslog.pcap (TCP 52173), sont declares par Decode As.
#
# Usage : tools/syslog_oracle.sh > tests/data/syslog_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, transport, longueur capturee de la
# charge, puis, pour les messages que tshark separe (virgules, `-` si
# vide) : comptages d'octets, facilites, gravites ; puis la version et,
# pour un message de la RFC 5424, les quatre champs d'en-tete que tshark
# nomme (hote, application, processus, identifiant de message), `-` si
# absents. Ce que tshark devine de l'en-tete d'un message BSD n'est pas
# garde : la crate rend ce contenu tel quel.
#
# tshark ne separe que les trames a comptage d'octets : d'un segment de
# messages termines par LF, il ne lit que le premier.
set -euo pipefail

root="${1:-pcaps_exemple}"
echo "# Genere par tools/syslog_oracle.sh avec $(tshark --version | head -1) : un datagramme ou un segment syslog par ligne."
echo "# Colonnes : capture, trame, transport, longueur de la charge, comptages d'octets, facilites, gravites, version, hote, application, processus, identifiant de message."
for capture in "$root/The-Ultimate-PCAP.pcapng" "$root"/protocols/syslog/*; do
    case "$capture" in *.pcap | *.pcapng | *.cap) ;; *) continue ;; esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -o tcp.analyze_sequence_numbers:FALSE \
        -d tcp.port==514,syslog -d tcp.port==601,syslog -d tcp.port==52173,syslog \
        -Y 'syslog.facility' -T fields -E separator='|' -E aggregator=';' \
        -e frame.number -e udp.payload -e tcp.payload -e syslog.msglen \
        -e syslog.facility -e syslog.level -e syslog.version \
        -e syslog.hostname -e syslog.appname -e syslog.procid -e syslog.msgid |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function list(value) { gsub(";", ",", value); return value == "" ? "-" : value }
            function text(value) { return value == "" || $7 == "" ? "-" : value }
            {
                transport = $2 != "" ? "udp" : "tcp"
                print capture, $1, transport, length($2 $3) / 2, list($4), list($5), list($6), \
                    list($7), text($8), text($9), text($10), text($11)
            }'
done
