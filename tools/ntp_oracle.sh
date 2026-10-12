#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/ntp_golden.rs.
#
# Une ligne par datagramme NTP (tshark `ntp`) des captures passees en
# argument ; par defaut les deux du corpus qui en portent : le poste IEC 61850
# de protocols/goose/ (52 datagrammes, requetes et reponses, v4 et v1, issue
# #161) et protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap (horodatage de
# l'ere 1, issue #162).
#
# Usage : tools/ntp_oracle.sh [capture...] > tests/data/ntp_tshark_oracle.tsv
# Colonnes (tabulation) : capture (chemin sous pcaps_exemple/protocols/),
# trame, port source, port destination, LI, version, mode, stratum, poll,
# precision, root delay, root dispersion (bruts), reference id
# (hexadecimal), horodatages reference, originate, receive, transmit
# (ISO 8601 en UTC, `NULL` quand nul).
set -euo pipefail

root="pcaps_exemple/protocols"
if [ "$#" -eq 0 ]; then
    set -- "$root/goose/iti_Sample_File_MMS_and_GOOSE.pcap" "$root/iec104/iti_JavaRMI_and_IEC_Misc.pcap"
fi
echo "# Genere par tools/ntp_oracle.sh avec $(tshark --version | head -1) : un datagramme NTP par ligne."
echo "# Colonnes : capture, trame, port source, port destination, LI, version, mode, stratum, poll,"
echo "# precision, root delay, root dispersion, reference id, horodatages reference, originate,"
echo "# receive, transmit (\`NULL\` quand nul)."
for capture in "$@"; do
    tshark -r "$capture" -Y "ntp" -T fields -E separator='|' \
        -e frame.number -e udp.srcport -e udp.dstport -e ntp.flags.li -e ntp.flags.vn -e ntp.flags.mode \
        -e ntp.stratum -e ntp.ppoll -e ntp.precision -e ntp.rootdelay -e ntp.rootdispersion -e ntp.refid \
        -e ntp.reftime -e ntp.org -e ntp.rec -e ntp.xmt |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="${capture#"$root/"}" '{
            for (i = 2; i <= 16; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        }'
done
