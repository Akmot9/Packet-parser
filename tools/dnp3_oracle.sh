#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/dnp3_golden.rs.
#
# Une ligne par segment TCP ou datagramme UDP a payload, sans reassemblage
# TCP (tcp.desegment_tcp_streams:FALSE) et avec le decodage DNP3 force sur le
# port 20001 (dnp3_read_p20001.pcap, port non standard). tshark reassemble
# les fragments applicatifs repartis sur plusieurs trames de liaison : les
# champs applicatifs d'un fragment en plusieurs trames n'apparaissent que sur
# la derniere, et sont ecartes ici (colonne `fir` a 0, ou `fin` a 0).
#
# Usage : tools/dnp3_oracle.sh [repertoire_de_captures] > tests/data/dnp3_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, porteur (tcp | udp), port source,
# port destination, longueur du payload, puis pour chaque trame de liaison
# (une seule par segment dans ce corpus) : longueur, controle, fonction de
# liaison, destination, source, CRC d'en-tete, controle de transport, fir,
# fin, sequence de transport ; puis l'application quand tshark la montre sur
# un fragment d'une seule trame : controle, fonction, IIN, objets
# (groupe/variation en hexadecimal, separes par `,`), prefixes, plages.
# `-` quand le champ n'existe pas.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/dnp3}"
echo "# Genere par tools/dnp3_oracle.sh avec $(tshark --version | head -1) : un segment ou datagramme a payload"
echo "# par ligne, sans reassemblage TCP, DNP3 force sur le port 20001. Colonnes : capture, trame, porteur,"
echo "# port source, port destination, longueur du payload, longueur de liaison, controle, fonction de"
echo "# liaison, destination, source, CRC d'en-tete, controle de transport, fir, fin, sequence, controle"
echo "# applicatif, fonction, IIN, objets, prefixes, plages (\`-\` quand absent)."
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -d tcp.port==20001,dnp3 \
        -Y "tcp.len > 0 || udp" -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e tcp.len -e udp.length \
        -e dnp3.len -e dnp3.ctl -e dnp3.ctl.prifunc -e dnp3.ctl.secfunc -e dnp3.dst -e dnp3.src -e dnp3.hdr.CRC \
        -e dnp3.tr.ctl -e dnp3.tr.fir -e dnp3.tr.fin -e dnp3.tr.seq \
        -e dnp3.al.ctl -e dnp3.al.func -e dnp3.al.iin -e dnp3.al.obj -e dnp3.al.objq.prefix -e dnp3.al.objq.range |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            carrier = ($2 != "") ? "tcp" : "udp"
            src = ($2 != "") ? $2 : $3
            dst = ($2 != "") ? $4 : $5
            len = ($2 != "") ? $6 : $7 - 8
            linkfunc = ($10 != "") ? $10 : $11
            for (i = 8; i <= 24; i++) if ($i == "") $i = "-"
            if (linkfunc == "") linkfunc = "-"
            print capture, $1, carrier, src, dst, len, $8, $9, linkfunc, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
        }'
done
