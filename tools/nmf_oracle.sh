#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/nmf_golden.rs.
#
# Une ligne par segment TCP a charge de pcaps_exemple/protocols/nmf/.
# tshark ne dissèque [MC-NMF] que sur le port 9389 : les ports des services
# de la capture (50001 et 50002) lui sont declares par -d. Son dissecteur ne
# reassemble pas : il lit aussi un segment de suite comme une suite
# d'enregistrements. Ces lignes restent dans l'oracle, avec ce que tshark en
# dit ; le test sait lesquelles sont des segments de suite.
#
# Usage : tools/nmf_oracle.sh > tests/data/nmf_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, longueur TCP, nombre
# d'enregistrements, types (decimal, separes par des virgules ; `-` au-dela
# de huit), taille de l'enveloppe, mode, encodage connu, longueur de Via ;
# `-` pour les champs absents.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/nmf}"
echo "# Genere par tools/nmf_oracle.sh avec $(tshark --version | head -1) : un segment a charge par ligne."
echo "# Colonnes : capture, trame, longueur TCP, enregistrements, types, taille d'enveloppe, mode, encodage connu, longueur de Via."
for capture in "$dir"/*.pcap; do
    tshark -r "$capture" -d tcp.port==50001,mc-nmf -d tcp.port==50002,mc-nmf -Y 'tcp.len > 0' \
        -T fields -E separator='|' \
        -e frame.number -e tcp.len -e mc-nmf.record_type -e mc-nmf.payload_length \
        -e mc-nmf.mode -e mc-nmf.known_encoding -e mc-nmf.via_length |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function dash(value) { return value == "" ? "-" : value }
            {
                count = split($3, types, ",")
                print capture, $1, $2, count, (count > 8 ? "-" : dash($3)), dash($4), dash($5), dash($6), dash($7)
            }'
done
