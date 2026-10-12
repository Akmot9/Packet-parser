#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/dis_golden.rs.
#
# Une trame par ligne, le decodage DIS force sur les trois ports du corpus
# (3000, l'usage ; 6993 et 22999, vus dans les captures) : tshark ne lit
# qu'un PDU par datagramme et ne s'arrete pas a la longueur declaree.
#
# Usage : tools/dis_oracle.sh [repertoire_de_captures] > tests/data/dis_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, version, exercice, type de PDU,
# famille, longueur declaree, site, application et entite du premier
# identifiant d'entite du corps, PDU Status (`-` avant la version 7).
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/dis}"
echo "# Genere par tools/dis_oracle.sh avec $(tshark --version | head -1) : une trame par ligne, decodage"
echo "# DIS force sur UDP 3000, 6993 et 22999. Colonnes : capture, trame, version, exercice, type de"
echo "# PDU, famille, longueur declaree, site, application et entite du premier identifiant d'entite"
echo "# du corps, PDU Status (\`-\` avant la version 7)."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -d udp.port==3000,dis -d udp.port==6993,dis -d udp.port==22999,dis \
        -Y dis -T fields -E separator='|' -E occurrence=f \
        -e frame.number -e dis.proto_ver -e dis.exer_id -e dis.pdu_type -e dis.proto_fam \
        -e dis.pdu_length -e dis.entity_id_site -e dis.entity_id_application -e dis.entity_id_entity \
        -e dis.pdu_status |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            for (i = 2; i <= 10; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        }'
done
