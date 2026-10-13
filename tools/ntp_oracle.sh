#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/ntp_golden.rs.
#
# Une ligne par datagramme NTP (tshark `ntp`) des captures passees en
# argument ; par defaut celles du corpus qui en portent : le poste IEC 61850
# de protocols/goose/ (52 datagrammes, requetes et reponses, v4 et v1, issue
# #161), protocols/iec104/iti_JavaRMI_and_IEC_Misc.pcap (horodatage de l'ere
# 1, issue #162), les captures nDPI de protocols/ntp/ (deux vrais NTP, et des
# datagrammes que l'ancienne sonde aveugle prenait pour du NTP, issue #164),
# et, lues en place, The-Ultimate-PCAP.pcapng (NTS, MS-SNTP, amonts IPv6,
# messages de controle, issue #165) et 4SICS-GeekLounge-151020.pcap.
#
# Usage : tools/ntp_oracle.sh [capture...] > tests/data/ntp_tshark_oracle.tsv
# Colonnes (tabulation) : capture (chemin sous pcaps_exemple/protocols/),
# trame, porteur (`udp`, ou `icmp` quand une erreur ICMP cite le datagramme),
# port source, port destination, LI, version, mode, stratum, poll,
# precision, root delay, root dispersion (bruts), reference id
# (hexadecimal), horodatages reference, originate, receive, transmit
# (ISO 8601 en UTC, `NULL` quand nul) ; `-` pour un champ absent (messages
# de controle du mode 6).
#
# Profil Wireshark vide : un Decode As ou une preference du poste qui
# regenere l'oracle ne doit rien changer.
set -euo pipefail

root="pcaps_exemple/protocols"
if [ "$#" -eq 0 ]; then
    set -- "$root/goose/iti_Sample_File_MMS_and_GOOSE.pcap" "$root/iec104/iti_JavaRMI_and_IEC_Misc.pcap" \
        "$root"/ntp/*.pcap* pcaps_exemple/The-Ultimate-PCAP.pcapng pcaps_exemple/4SICS-GeekLounge-151020.pcap
fi
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT
export WIRESHARK_CONFIG_DIR="$profile"

echo "# Genere par tools/ntp_oracle.sh avec $(tshark --version | head -1) : un datagramme NTP par ligne."
echo "# Colonnes : capture, trame, porteur, port source, port destination, LI, version, mode, stratum,"
echo "# poll, precision, root delay, root dispersion, reference id, horodatages reference, originate,"
echo "# receive, transmit (\`NULL\` quand nul)."
for capture in "$@"; do
    case "$capture" in
        "$root"/*) name="${capture#"$root/"}" ;;
        pcaps_exemple/*) name="../${capture#pcaps_exemple/}" ;;
        *) name="$capture" ;;
    esac
    tshark -r "$capture" -Y "ntp" -T fields -E separator='|' \
        -e frame.number -e udp.srcport -e udp.dstport -e ntp.flags.li -e ntp.flags.vn -e ntp.flags.mode \
        -e ntp.stratum -e ntp.ppoll -e ntp.precision -e ntp.rootdelay -e ntp.rootdispersion -e ntp.refid \
        -e ntp.reftime -e ntp.org -e ntp.rec -e ntp.xmt -e frame.protocols |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$name" '{
            carrier = ($17 ~ /:icmp(v6)?:/) ? "icmp" : "udp"
            for (i = 2; i <= 16; i++) if ($i == "") $i = "-"
            print capture, $1, carrier, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        }'
done
