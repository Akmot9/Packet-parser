#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/mqtt_golden.rs.
#
# Une ligne par paquet MQTT, dans les captures MQTT 5 du tracker Wireshark
# versees dans pcaps_exemple/protocols/mqtt/ (wireshark_*.pcapng). Celles de
# l'issue #15428 passent par le port 1888, que tshark ne decode pas en MQTT
# sans `-d`.
#
# Usage : tools/mqtt_oracle.sh > tests/data/mqtt_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, type de paquet, remaining length.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/mqtt}"
echo "# Genere par tools/mqtt_oracle.sh avec $(tshark --version | head -1) : un paquet MQTT par ligne,"
echo "# captures wireshark_* de protocols/mqtt/. Colonnes : capture, trame, type, remaining length."
for capture in "$dir"/wireshark_*; do
    tshark -r "$capture" -d tcp.port==1888,mqtt -Y mqtt -T fields -E separator='|' \
        -e frame.number -e mqtt.msgtype -e mqtt.len |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            print capture, $1, $2, $3
        }'
done
