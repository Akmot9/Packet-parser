#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/rdp_golden.rs.
#
# Une ligne par segment TCP a payload, sans reassemblage
# (tcp.desegment_tcp_streams:FALSE) : la vue d'un parseur sans etat.
#
# Usage : tools/rdp_oracle.sh [repertoire_de_captures] > tests/data/rdp_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, port source, port destination,
# longueur du payload, longueur TPKT, type COTP (quartet, `0x0e` CR, `0x0d`
# CC, `0x0f` DT), jeton ou cookie X.224, type de negociation, protocoles
# demandes, protocole retenu, ConnectMCSPDU (101, 102), DomainMCSPDU (choix
# PER), dernier protocole de la trame selon tshark (rdp, t125, t124, tls,
# data, tcp), retransmission TCP (`1` quand tshark la signale et ne dissèque
# pas, `-` sinon). `-` quand le champ n'existe pas.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/rdp}"
echo "# Genere par tools/rdp_oracle.sh avec $(tshark --version | head -1) : un segment TCP a payload par ligne,"
echo "# sans reassemblage. Colonnes : capture, trame, port source, port destination, longueur du payload,"
echo "# longueur TPKT, type COTP, jeton X.224, type de negociation, protocoles demandes, protocole retenu,"
echo "# ConnectMCSPDU, DomainMCSPDU, dernier protocole de la trame, retransmission TCP (\`-\` quand absent)."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -Y "tcp.len > 0" \
        -T fields -E separator='|' -E occurrence=f \
        -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.len -e tpkt.length -e cotp.type \
        -e rdp.rt_cookie -e rdp.neg_type -e rdp.negReq.requestedProtocols -e rdp.negReq.selectedProtocol \
        -e t125.ConnectMCSPDU -e t124.DomainMCSPDU -e frame.protocols -e tcp.analysis.retransmission |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            n = split($13, protocols, ":")
            last = protocols[n]
            for (i = 5; i <= 12; i++) if ($i == "") $i = "-"
            retransmission = ($14 == "") ? "-" : "1"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, last, retransmission
        }'
done
