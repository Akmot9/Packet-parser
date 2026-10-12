#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/goose_golden.rs.
#
# Une ligne par trame GOOSE (EtherType 0x88B8, avec ou sans etiquette VLAN).
#
# Usage : tools/goose_oracle.sh [repertoire_de_captures] > tests/data/goose_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, VLAN, APPID, longueur, reserve 1,
# reserve 2, gocbRef, timeAllowedtoLive, datSet, goID, stNum, sqNum,
# simulation, confRev, ndsCom, numDatSetEntries, nombre d'elements de
# allData, codes des elements (separes par `,`). `-` quand le champ n'existe
# pas.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/goose}"
echo "# Genere par tools/goose_oracle.sh avec $(tshark --version | head -1) : une trame GOOSE par ligne."
echo "# Colonnes : capture, trame, VLAN, APPID, longueur, reserve 1, reserve 2, gocbRef, timeAllowedtoLive,"
echo "# datSet, goID, stNum, sqNum, simulation, confRev, ndsCom, numDatSetEntries, elements de allData,"
echo "# codes des elements (\`-\` quand absent)."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -Y "goose" -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e vlan.id -e goose.appid -e goose.length -e goose.reserve1 -e goose.reserve2 \
        -e goose.gocbRef -e goose.timeAllowedtoLive -e goose.datSet -e goose.goID -e goose.stNum -e goose.sqNum \
        -e goose.simulation -e goose.confRev -e goose.ndsCom -e goose.numDatSetEntries -e goose.allData -e goose.Data |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            for (i = 2; i <= 18; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
        }'
done
