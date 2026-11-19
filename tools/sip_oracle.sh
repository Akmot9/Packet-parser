#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/sip_golden.rs (#342).
#
# Une ligne par trame que tshark etiquette SIP, dans les captures de
# pcaps_exemple/protocols/sip/ et dans pcaps_exemple/The-Ultimate-PCAP.pcapng.
# Reassemblage IP et TCP coupe, comme la crate. Les fragments IPv4 sont
# exclus : la crate ne lit pas le transport d'un datagramme fragmente (#105),
# ce qui ecarte la trame 15114 de The-Ultimate-PCAP, premier fragment d'un
# INVITE de 2 017 octets.
#
# Usage : tools/sip_oracle.sh > tests/data/sip_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, methode ou code de statut, numero
# CSeq, methode CSeq, Content-Length (`-` s'il est absent).
set -euo pipefail

dir="${1:-pcaps_exemple}"
echo "# Genere par tools/sip_oracle.sh avec $(tshark --version | head -1) : une trame SIP par ligne."
echo "# Colonnes : capture, trame, methode ou code, numero CSeq, methode CSeq, Content-Length."
for capture in "$dir"/protocols/sip/* "$dir"/The-Ultimate-PCAP.pcapng; do
    case "$capture" in *.pcap | *.pcapng) ;; *) continue ;; esac
    tshark -r "$capture" -o ip.defragment:FALSE -o tcp.desegment_tcp_streams:FALSE \
        -Y 'sip && !(ip.flags.mf == 1) && !(ip.frag_offset > 0)' \
        -T fields -E separator='|' \
        -e frame.number -e sip.Method -e sip.Status-Code -e sip.CSeq.seq -e sip.CSeq.method \
        -e sip.Content-Length |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function dash(value) { return value == "" ? "-" : value }
            {
                start = $2 != "" ? $2 : $3
                print capture, $1, start, $4, $5, dash($6)
            }'
done
