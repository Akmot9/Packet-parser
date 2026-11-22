#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/rtcp_golden.rs.
#
# Une ligne par datagramme RTCP de trois captures : un appel SIP
# (wireshark_aaa.pcap), un appel LINE (ndpi_line.pcap) et un extrait de
# terrain censure (terrain_rtcp_censure.pcap), dont les ports sont declares
# a tshark par -d. L'heuristique `rtp_udp` reste coupee : elle prend pour du
# RTCP des datagrammes de type 210 de The-Ultimate-PCAP qui n'en sont pas.
#
# Usage : tools/rtcp_oracle.sh > tests/data/rtcp_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, longueur UDP (en-tete compris),
# types des paquets, longueurs en mots moins un, SSRC des emetteurs,
# horodatage NTP (poids fort, poids faible), horodatage RTP, nombre de
# paquets et d'octets du SR ; listes separees par des virgules, `-` pour les
# champs absents.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols}"
echo "# Genere par tools/rtcp_oracle.sh avec $(tshark --version | head -1) : un datagramme RTCP par ligne."
echo "# Colonnes : capture, trame, longueur UDP, types, longueurs, SSRC emetteurs, NTP msw, NTP lsw, horodatage RTP, paquets, octets."
for capture in "$dir/sip/wireshark_aaa.pcap" "$dir/ntp/ndpi_line.pcap" "$dir/rtcp/terrain_rtcp_censure.pcap"; do
    tshark -r "$capture" -d udp.port==50000,rtcp -d udp.port==50001,rtcp -d udp.port==50002,rtcp \
        -Y 'rtcp && !icmp' -T fields -E separator='|' \
        -e frame.number -e udp.length -e rtcp.pt -e rtcp.length -e rtcp.senderssrc \
        -e rtcp.timestamp.ntp.msw -e rtcp.timestamp.ntp.lsw -e rtcp.timestamp.rtp \
        -e rtcp.sender.packetcount -e rtcp.sender.octetcount |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function dash(value) { return value == "" ? "-" : value }
            { print capture, $1, $2, $3, $4, dash($5), dash($6), dash($7), dash($8), dash($9), dash($10) }'
done
