#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/stanag5066_golden.rs.
#
# Un segment TCP par ligne, tel que tshark dissèque le SIS SANS reassemblage
# (`tcp.desegment_tcp_streams:FALSE`) : la vue d'un parseur stateless, ou un
# S_PDU coupe entre deux segments est vu dans son premier segment, et ou un
# segment de continuation (sans preambule) n'est pas du SIS.
#
# Usage : tools/stanag5066_oracle.sh [repertoire_de_captures] > tests/data/stanag5066_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, types des S_PDU du segment, tailles
# de primitive, adresses de noeud (ordre de dissection), SAP de destination
# des primitives 20 a 27 (groupes par type), tailles d'U_PDU annoncees
# (idem), SAP source des indications (21 puis 25), modes de transmission des
# indications (21 puis 25), TTL des requetes (20 puis 24), SAP et rang des
# S_BIND_REQUEST, SAP et MTU des S_BIND_ACCEPTED, motifs (04, 05, 23, 27).
# Listes separees par des virgules, `-` si vide.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/stanag5066}"
echo "# Genere par tools/stanag5066_oracle.sh avec $(tshark --version | head -1) : un segment TCP par"
echo "# ligne, sans reassemblage (tcp.desegment_tcp_streams:FALSE). Colonnes : capture, trame, types,"
echo "# tailles de primitive, adresses de noeud, SAP destination (20-27), tailles d'U_PDU (20-27),"
echo "# SAP source (21, 25), modes de transmission (21, 25), TTL (20, 24), SAP et rang (01),"
echo "# SAP et MTU (03), motifs (04, 05, 23, 27). \`-\` si vide."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -Y s5066sis \
        -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e s5066sis.type -e s5066sis.size -e s5066sis.address.address \
        -e s5066sis.20.sapid -e s5066sis.21.sapid -e s5066sis.22.sapid -e s5066sis.23.sapid \
        -e s5066sis.24.sapid -e s5066sis.25.sapid -e s5066sis.26.sapid -e s5066sis.27.sapid \
        -e s5066sis.20.size -e s5066sis.21.size -e s5066sis.22.size -e s5066sis.23.size \
        -e s5066sis.24.size -e s5066sis.25.size -e s5066sis.26.size -e s5066sis.27.size \
        -e s5066sis.21.src_sapid -e s5066sis.25.src_sapid \
        -e s5066sis.21.txmode -e s5066sis.25.txmode \
        -e s5066sis.20.ttl -e s5066sis.24.ttl \
        -e s5066sis.01.sapid -e s5066sis.01.rank -e s5066sis.03.sapid -e s5066sis.03.mtu \
        -e s5066sis.04.reason -e s5066sis.05.reason -e s5066sis.23.reason -e s5066sis.27.reason |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
        function join(from, to,    i, out) {
            out = ""
            for (i = from; i <= to; i++) if ($i != "") out = (out == "") ? $i : out "," $i
            return (out == "") ? "-" : out
        }
        {
            for (i = 2; i <= 4; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4, join(5, 12), join(13, 20), join(21, 22), join(23, 24), \
                join(25, 26), join(27, 28), join(29, 30), join(31, 34)
        }'
done
