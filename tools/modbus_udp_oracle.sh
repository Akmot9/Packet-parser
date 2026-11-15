#!/usr/bin/env bash
# Regenere l'oracle tshark du test Modbus sur UDP de tests/modbus_golden.rs
# (#257).
#
# Une ligne par datagramme UDP que tshark decode en Modbus (`mbudp`, port
# 502) dans les captures passees en argument ; par defaut
# protocols/modbus/modbus-udp.pcapng. Le dissecteur `mbudp` reprend les
# champs `mbtcp.*` de l'enveloppe MBAP.
#
# Usage : tools/modbus_udp_oracle.sh [capture...] > tests/data/modbus_udp_tshark_oracle.tsv
# Colonnes (tabulation) : celles de tools/modbus_oracle.sh, les ports etant
# ceux d'UDP.
set -euo pipefail

root="pcaps_exemple/protocols"
if [ "$#" -eq 0 ]; then
    set -- "$root"/modbus/modbus-udp.pcapng
fi
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT
export WIRESHARK_CONFIG_DIR="$profile"

echo "# Genere par tools/modbus_udp_oracle.sh avec $(tshark --version | head -1) : un datagramme Modbus par ligne."
echo "# Colonnes : capture, trame, port source, port destination, transactions, longueurs, unites,"
echo "# codes fonction, codes d'exception."
for capture in "$@"; do
    case "$capture" in
        "$root"/*) name="${capture#"$root/"}" ;;
        pcaps_exemple/*) name="../${capture#pcaps_exemple/}" ;;
        *) name="$capture" ;;
    esac
    tshark -r "$capture" -Y "mbudp" -T fields -E separator='|' \
        -E occurrence=a -E aggregator=, \
        -e frame.number -e udp.srcport -e udp.dstport -e mbtcp.trans_id -e mbtcp.len -e mbtcp.unit_id \
        -e modbus.func_code -e modbus.exception_code |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$name" '{
            for (i = 2; i <= 8; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8
        }'
done
