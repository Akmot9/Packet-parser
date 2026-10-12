#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/postgresql_golden.rs.
#
# Une ligne par segment TCP a payload, sans reassemblage
# (tcp.desegment_tcp_streams:FALSE) : la vue d'un parseur sans etat. Les deux
# captures negatives (HTTP et MySQL sur le port 5432) sont parcourues comme
# les autres : ce que tshark y etiquette `pgsql` est son propre faux positif.
#
# Usage : tools/postgresql_oracle.sh [repertoire_de_captures] > tests/data/postgresql_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, port source, port destination,
# longueur du payload TCP, types des messages pgsql (separes par `|`, `-` si
# aucun), longueurs des messages (separees par `,`, `-` si aucune),
# retransmission TCP (`1` quand tshark la signale et ne dissèque pas, `-` sinon).
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/postgresql}"
echo "# Genere par tools/postgresql_oracle.sh avec $(tshark --version | head -1) : un segment TCP a payload"
echo "# par ligne, sans reassemblage. Colonnes : capture, trame, port source, port destination, longueur"
echo "# du payload, types des messages pgsql (\`|\`, \`-\` si aucun), longueurs des messages (\`,\`),"
echo "# retransmission TCP (\`1\` ou \`-\`)."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -Y "tcp.len > 0" \
        -T fields -E separator='	' -E occurrence=a -E aggregator='|' \
        -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.len -e pgsql.type -e pgsql.length \
        -e tcp.analysis.retransmission |
        LC_ALL=C awk -F'\t' -v OFS='\t' -v capture="$(basename "$capture")" '{
            types = ($5 == "") ? "-" : $5
            lengths = ($6 == "") ? "-" : $6
            gsub(/\|/, ",", lengths)
            retransmission = ($7 == "") ? "-" : "1"
            print capture, $1, $2, $3, $4, types, lengths, retransmission
        }'
done
