#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/bacnet_golden.rs.
#
# Un datagramme BACnet/IP par ligne (udp.port 47808). Les datagrammes UDP
# vides de iti_bacnet_test.pcap n'ont pas de ligne.
#
# Usage : tools/bacnet_oracle.sh [repertoire_de_captures] > tests/data/bacnet_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, port source, port destination,
# longueur du payload, fonction BVLC, longueur BVLC, version NPDU, controle,
# DNET, DLEN, SNET, SLEN, compte de sauts, type de message reseau, type
# d'APDU, identifiant d'invocation, service confirme, service non confirme.
# `-` quand le champ n'existe pas.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/bacnet}"
echo "# Genere par tools/bacnet_oracle.sh avec $(tshark --version | head -1) : un datagramme BACnet/IP par ligne."
echo "# Colonnes : capture, trame, port source, port destination, longueur du payload, fonction BVLC, longueur"
echo "# BVLC, version NPDU, controle, DNET, DLEN, SNET, SLEN, compte de sauts, type de message reseau, type"
echo "# d'APDU, identifiant d'invocation, service confirme, service non confirme (\`-\` quand absent)."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -Y "bvlc" -T fields -E separator='|' -E occurrence=f \
        -e frame.number -e udp.srcport -e udp.dstport -e udp.length \
        -e bvlc.function -e bvlc.length -e bacnet.version -e bacnet.control -e bacnet.dnet -e bacnet.dlen \
        -e bacnet.snet -e bacnet.slen -e bacnet.hopc -e bacnet.mesgtyp \
        -e bacapp.type -e bacapp.invoke_id -e bacapp.confirmed_service -e bacapp.unconfirmed_service |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            for (i = 5; i <= 18; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4 - 8, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
        }'
done
