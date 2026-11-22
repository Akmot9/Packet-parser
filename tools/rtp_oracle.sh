#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/rtp_golden.rs (#353).
#
# Une ligne par trame que tshark etiquette RTP, dans quatre captures deja
# versionnees. Sans signalisation, tshark ne nomme pas RTP : son heuristique
# `rtp_udp` est activee, comme la sonde aveugle de la crate. Le dissecteur
# T.38 est coupe : dans la capture de fax, apres le re-INVITE, tshark
# attribue a T.38 les 2 010 paquets G.711 qui circulent encore sur les
# ports negocies. Les paquets RTP cites dans une erreur ICMP sont exclus,
# la crate ne lisant pas la charge d'un message ICMP. Reassemblage IP coupe,
# comme la crate.
#
# Usage : tools/rtp_oracle.sh > tests/data/rtp_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, type de charge, marqueur (0 ou 1),
# numero de sequence, horodatage, SSRC, nombre de CSRC, longueur de
# l'extension en mots (`-` sans extension), octets de bourrage (`-` sans
# bourrage), longueur UDP (en-tete de huit octets compris).
set -euo pipefail

dir="${1:-pcaps_exemple}"
echo "# Genere par tools/rtp_oracle.sh avec $(tshark --version | head -1) : une trame RTP par ligne."
echo "# Colonnes : capture, trame, type de charge, marqueur, sequence, horodatage, SSRC, CSRC, extension, bourrage, longueur UDP."
for capture in \
    "$dir"/The-Ultimate-PCAP.pcapng \
    "$dir"/protocols/ntp/ndpi_line.pcap \
    "$dir"/protocols/sip/wireshark_FAX-Call-t38-CA-TDM-SIP-FB-1.pcap \
    "$dir"/protocols/sip/wireshark_aaa.pcap; do
    tshark -r "$capture" -o ip.defragment:FALSE -o rtp.heuristic_rtp:TRUE \
        --enable-heuristic rtp_udp --disable-protocol t38 \
        -Y 'rtp && !icmp' \
        -T fields -E separator='|' -E occurrence=f \
        -e frame.number -e rtp.p_type -e rtp.marker -e rtp.seq -e rtp.timestamp \
        -e rtp.ssrc -e rtp.cc -e rtp.ext.len -e rtp.padding.count -e udp.length |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function dash(value) { return value == "" ? "-" : value }
            { print capture, $1, $2, ($3 == "True" ? 1 : 0), $4, $5, $6, $7, dash($8), dash($9), $10 }'
done
