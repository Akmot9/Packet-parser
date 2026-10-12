#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/ipsec_golden.rs.
#
# Une trame par ligne, IKE (ISAKMP) et ESP, natifs ou encapsules dans UDP
# 4500 (RFC 3948). Les payloads Proposal (2) et Transform (3) de tshark sont
# ecartes : ils vivent a l'interieur d'un Security Association, le decodeur
# ne lit que la chaine de premier niveau.
#
# Usage : tools/ipsec_oracle.sh [repertoire_de_captures] > tests/data/ipsec_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, protocole (ike | esp), porteur
# (udp : UDP sans 4500 ; natt : UDP 4500 ; native : protocole IP 50), SPI
# (initiateur pour IKE, SPI pour ESP), SPI repondeur, version, type
# d'echange, drapeaux, identifiant de message, longueur, types des payloads
# de premier niveau, leurs longueurs, numero de sequence ESP. `-` quand le
# champ n'existe pas pour le protocole.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/ipsec}"
echo "# Genere par tools/ipsec_oracle.sh avec $(tshark --version | head -1) : une trame par ligne, IKE et ESP,"
echo "# natifs ou dans UDP 4500 ; payloads Proposal (2) et Transform (3) ecartes (imbriques dans un SA)."
echo "# Colonnes : capture, trame, protocole, porteur, SPI initiateur ou ESP, SPI repondeur, version, type"
echo "# d'echange, drapeaux, identifiant de message, longueur, types de payloads, longueurs de payloads,"
echo "# sequence ESP."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -Y "isakmp || esp" -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e ip.proto -e udp.srcport -e udp.dstport \
        -e isakmp.ispi -e isakmp.rspi -e isakmp.version -e isakmp.exchangetype -e isakmp.flags \
        -e isakmp.messageid -e isakmp.length -e isakmp.typepayload -e isakmp.payloadlength \
        -e esp.spi -e esp.sequence |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            if ($14 != "") {
                proto = "esp"
                carrier = ($2 == 50) ? "native" : "natt"
                print capture, $1, proto, carrier, $14, "-", "-", "-", "-", "-", "-", "-", "-", $15
                next
            }
            carrier = ($3 == 4500 || $4 == 4500) ? "natt" : "udp"
            nt = split($12, t, ","); nl = split($13, l, ",")
            types = ""; lengths = ""
            for (i = 1; i <= nt; i++) {
                if (t[i] == 2 || t[i] == 3) continue
                types = (types == "") ? t[i] : types "," t[i]
                lengths = (lengths == "") ? l[i] : lengths "," l[i]
            }
            if (types == "") { types = "-"; lengths = "-" }
            print capture, $1, "ike", carrier, $5, $6, $7, $8, $9, $10, $11, types, lengths, "-"
        }'
done
