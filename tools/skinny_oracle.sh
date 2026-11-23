#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/skinny_golden.rs (#368).
#
# Une ligne par segment TCP que tshark dissèque comme Skinny dans les
# captures de pcaps_exemple/protocols/skinny/. Trois reglages rendent
# tshark sans etat, comme la crate :
# - reassemblage TCP et Skinny coupes : chaque segment est lu seul ;
# - analyse des numeros de sequence coupee : sans elle, tshark ne passe pas
#   une retransmission a son dissecteur.
#
# Usage : tools/skinny_oracle.sh > tests/data/skinny_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, longueur TCP, puis, pour les
# messages du segment et separes par des virgules : longueurs, versions
# d'en-tete et identifiants de message, en decimal.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/skinny}"
echo "# Genere par tools/skinny_oracle.sh avec $(tshark --version | head -1) : un segment Skinny par ligne."
echo "# Colonnes : capture, trame, longueur TCP, longueurs, versions d'en-tete, identifiants (un par message)."
for capture in "$dir"/*; do
    case "$capture" in *.pcap | *.pcapng | *.cap) ;; *) continue ;; esac
    # wireshark_8805_packets.cap finit au milieu d'un enregistrement (six
    # octets apres la trame 759) : tshark lit tout puis sort en erreur.
    {
        tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -o skinny.desegment:FALSE \
            -o tcp.analyze_sequence_numbers:FALSE \
            -Y 'skinny' -T fields -E separator='|' \
            -e frame.number -e tcp.len -e skinny.data_length -e skinny.hdr_version -e skinny.messageId ||
            [[ "$capture" == */wireshark_8805_packets.cap ]]
    } |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            {
                # tshark rend les versions en hexadecimal (0x00000012).
                count = split($4, versions, ",")
                decimal = ""
                for (i = 1; i <= count; i++) {
                    decimal = decimal (i > 1 ? "," : "") strtonum(versions[i])
                }
                print capture, $1, $2, $3, decimal, $5
            }'
done
