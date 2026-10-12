#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/iec104_golden.rs.
#
# Une ligne par segment TCP a payload, sans reassemblage
# (tcp.desegment_tcp_streams:FALSE) : la vue d'un parseur sans etat. Les
# champs multiples (plusieurs APDU par segment) sont separes par `,`, dans
# l'ordre des APDU ; `tx` n'existe que pour le format I, `rx` pour I et S,
# `utype` pour U, les champs d'ASDU pour I.
#
# Usage : tools/iec104_oracle.sh [repertoire_de_captures] > tests/data/iec104_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, port source, port destination,
# longueur du payload, longueurs d'APDU, formats (0 I, 1 S, 3 U), fonctions
# U (controle >> 2), N(S), N(R), types d'ASDU, SQ, nombres d'objets, causes,
# adresses d'origine, adresses communes, adresses d'objets, retransmission.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/iec104}"
echo "# Genere par tools/iec104_oracle.sh avec $(tshark --version | head -1) : un segment TCP a payload par ligne,"
echo "# sans reassemblage, champs multiples separes par \`,\` dans l'ordre des APDU. Colonnes : capture, trame,"
echo "# port source, port destination, longueur du payload, longueurs d'APDU, formats, fonctions U, N(S), N(R),"
echo "# types d'ASDU, SQ, nombres d'objets, causes, adresses d'origine, adresses communes, adresses d'objets,"
echo "# retransmission TCP (\`-\` quand absent)."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -Y "tcp.len > 0" \
        -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.len \
        -e iec60870_104.apdulen -e iec60870_104.type -e iec60870_104.utype -e iec60870_104.tx -e iec60870_104.rx \
        -e iec60870_asdu.typeid -e iec60870_asdu.sq -e iec60870_asdu.numix -e iec60870_asdu.causetx \
        -e iec60870_asdu.oa -e iec60870_asdu.addr -e iec60870_asdu.ioa -e tcp.analysis.retransmission |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            for (i = 5; i <= 16; i++) if ($i == "") $i = "-"
            retransmission = ($17 == "") ? "-" : "1"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, retransmission
        }'
done
