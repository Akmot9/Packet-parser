#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/rtps_golden.rs.
#
# Une ligne par trame RTPS que tshark dissèque SANS reassemblage IP : les
# trames fragmentees (MF ou offset non nul) sont exclues — un parseur sans
# etat ne voit jamais le message qu'elles composent.
#
# Usage : tools/rtps_oracle.sh [repertoire_de_captures] > tests/data/rtps_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, version (major.minor), vendorId,
# guidPrefix, submessageId de chaque sous-message (hexa, virgules),
# octetsToNextHeader de chacun, readerEntityId puis writerEntityId des
# sous-messages qui en portent, et les numeros de sequence que tshark
# expose sous `rtps.sm.seqNumber` (writerSN des DATA/DATA_FRAG/NACK_FRAG/
# HEARTBEAT_FRAG, first et last des HEARTBEAT), dans l'ordre ; `-` si vide.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/rtps}"
echo "# Genere par tools/rtps_oracle.sh avec $(tshark --version | head -1) : une ligne par trame RTPS,"
echo "# sans reassemblage IP (fragments exclus). Colonnes : capture, trame, version, vendorId,"
echo "# guidPrefix, submessageIds, octetsToNextHeader, readerEntityIds, writerEntityIds, seqNumbers"
echo "# (rtps.sm.seqNumber : writerSN des DATA/DATA_FRAG/NACK_FRAG/HEARTBEAT_FRAG, first et last des"
echo "# HEARTBEAT). Listes separees par des virgules, \`-\` si vide."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -Y 'rtps && !(ip.flags.mf == 1 || ip.frag_offset > 0)' \
        -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e rtps.version.major -e rtps.version.minor -e rtps.vendorId \
        -e rtps.guidPrefix -e rtps.sm.id -e rtps.sm.octetsToNextHeader \
        -e rtps.sm.rdEntityId -e rtps.sm.wrEntityId -e rtps.sm.seqNumber |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            # Les champs d en-tete sont repetes par sous-message : premier seul.
            split($2, major, ","); split($3, minor, ","); split($4, vendor, ","); split($5, guid, ",")
            for (i = 6; i <= 10; i++) if ($i == "") $i = "-"
            print capture, $1, major[1] "." minor[1], vendor[1], guid[1], $6, $7, $8, $9, $10
        }'
done
