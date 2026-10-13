#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/modbus_golden.rs.
#
# Une ligne par segment TCP que tshark decode en Modbus/TCP (`mbtcp`, port
# 502) dans les captures passees en argument ; par defaut celles du corpus
# qui en portent : protocols/modbus/, protocols/umas/ et, lue en place,
# The-Ultimate-PCAP.pcapng, dont les segments LDAP etaient pris pour du
# Modbus par la sonde aveugle (#167).
#
# Usage : tools/modbus_oracle.sh [capture...] > tests/data/modbus_tshark_oracle.tsv
# Colonnes (tabulation) : capture (chemin sous pcaps_exemple/protocols/),
# trame, port source, port destination, puis une liste par segment, une
# valeur par en-tete MBAP : identifiants de transaction, longueurs,
# identifiants d'unite, codes fonction (sans le bit d'exception), et les
# codes d'exception des seules reponses d'exception (`-` s'il n'y en a pas).
#
# Vue d'un parseur sans etat : pas de reassemblage TCP, profil Wireshark
# vide.
set -euo pipefail

root="pcaps_exemple/protocols"
if [ "$#" -eq 0 ]; then
    set -- "$root"/modbus/*.pcap* "$root"/umas/*.pcap* pcaps_exemple/The-Ultimate-PCAP.pcapng
fi
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT
export WIRESHARK_CONFIG_DIR="$profile"

echo "# Genere par tools/modbus_oracle.sh avec $(tshark --version | head -1) : un segment Modbus/TCP par ligne."
echo "# Colonnes : capture, trame, port source, port destination, transactions, longueurs, unites,"
echo "# codes fonction, codes d'exception."
for capture in "$@"; do
    case "$capture" in
        "$root"/*) name="${capture#"$root/"}" ;;
        pcaps_exemple/*) name="../${capture#pcaps_exemple/}" ;;
        *) name="$capture" ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -Y "mbtcp" -T fields -E separator='|' \
        -E occurrence=a -E aggregator=, \
        -e frame.number -e tcp.srcport -e tcp.dstport -e mbtcp.trans_id -e mbtcp.len -e mbtcp.unit_id \
        -e modbus.func_code -e modbus.exception_code |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$name" '{
            for (i = 2; i <= 8; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8
        }'
done
