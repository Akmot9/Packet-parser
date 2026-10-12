#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/radius_golden.rs.
#
# Une ligne par paquet RADIUS, dans les captures de pcaps_exemple/protocols/radius/
# et dans The-Ultimate-PCAP.pcapng a la racine de pcaps_exemple/ (ses 72
# paquets RADIUS de 2022, un commutateur et un serveur NPS).
#
# Usage : tools/radius_oracle.sh > tests/data/radius_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, port source, port destination, code,
# identifiant, longueur, authentificateur (hexadecimal), types des attributs
# (separes par `,`), longueurs des attributs, identifiants de vendeur des
# Vendor-Specific (`-` quand il n'y en a pas).
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/radius}"
echo "# Genere par tools/radius_oracle.sh avec $(tshark --version | head -1) : un paquet RADIUS par ligne,"
echo "# captures de protocols/radius/ et The-Ultimate-PCAP.pcapng. Colonnes : capture, trame, port source,"
echo "# port destination, code, identifiant, longueur, authentificateur, types des attributs, longueurs"
echo "# des attributs, identifiants de vendeur (\`-\` si aucun)."
for capture in "$dir"/* "$(dirname "$dir")/../The-Ultimate-PCAP.pcapng"; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -Y radius -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e udp.srcport -e udp.dstport -e radius.code -e radius.id -e radius.length \
        -e radius.authenticator -e radius.avp.type -e radius.avp.length -e radius.avp.vendor_id |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            types = ($8 == "") ? "-" : $8
            lengths = ($9 == "") ? "-" : $9
            vendors = ($10 == "") ? "-" : $10
            gsub(/:/, "", $7)
            print capture, $1, $2, $3, $4, $5, $6, $7, types, lengths, vendors
        }'
done
