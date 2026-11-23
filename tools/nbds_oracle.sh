#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/nbds_golden.rs (#377).
#
# Une ligne par datagramme que tshark dissèque comme NetBIOS Datagram
# Service (UDP 138) dans toutes les captures de pcaps_exemple/protocols/ :
# le dossier netbios/ et les datagrammes epars des autres dossiers.
#
# Usage : tools/nbds_oracle.sh > tests/data/nbds_tshark_oracle.tsv
# Colonnes (tabulation) : capture (chemin sous pcaps_exemple/protocols/),
# trame, longueur de la charge UDP, type de message, drapeaux, identifiant
# du datagramme, adresse et port source, longueur annoncee, decalage du
# fragment (tous en decimal), nom source, nom destination. Les noms sont
# ceux de tshark : quinze octets sans les espaces de fin, un octet non
# imprimable en `<xx>`, puis le suffixe en `<xx>`.
set -euo pipefail

root="${1:-pcaps_exemple/protocols}"
echo "# Genere par tools/nbds_oracle.sh avec $(tshark --version | head -1) : un datagramme NBDS par ligne."
echo "# Colonnes : capture, trame, longueur UDP, type, drapeaux, identifiant, adresse source, port source, longueur annoncee, decalage, nom source, nom destination."
find "$root" -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) | LC_ALL=C sort |
    while IFS= read -r capture; do
        # skinny/wireshark_8805_packets.cap finit au milieu d'un
        # enregistrement : tshark lit tout puis sort en erreur.
        {
            tshark -r "$capture" -Y 'nbdgm' -T fields -E separator='|' \
                -e frame.number -e udp.length -e nbdgm.type -e nbdgm.flags -e nbdgm.dgram_id \
                -e nbdgm.src.ip -e nbdgm.src.port -e nbdgm.dgram_len -e nbdgm.pkt_offset \
                -e nbdgm.source_name -e nbdgm.destination_name 2>/dev/null ||
                [[ "$capture" == */wireshark_8805_packets.cap ]]
        } |
            LC_ALL=C awk -F'|' -v OFS='\t' -v capture="${capture#"$root"/}" '
                { print capture, $1, $2 - 8, $3, strtonum($4), strtonum($5), $6, $7, $8, $9, $10, $11 }'
    done
