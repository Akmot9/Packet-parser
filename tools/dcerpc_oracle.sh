#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/dcerpc_golden.rs.
#
# Une ligne par segment TCP que tshark dissèque comme DCE/RPC oriente
# connexion dans pcaps_exemple/The-Ultimate-PCAP.pcapng, hors SMB (tubes
# nommes). Reassemblage TCP et DCE/RPC coupes : la crate lit segment par
# segment.
#
# Usage : tools/dcerpc_oracle.sh > tests/data/dcerpc_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, longueur TCP, version mineure,
# type de PDU, drapeaux (hexadecimal), representation des donnees, longueur
# du fragment, longueur d'authentification, identifiant d'appel, numero
# d'operation (`-` hors requete).
set -euo pipefail

capture="${1:-pcaps_exemple/The-Ultimate-PCAP.pcapng}"
echo "# Genere par tools/dcerpc_oracle.sh avec $(tshark --version | head -1) : un segment DCE/RPC par ligne."
echo "# Colonnes : capture, trame, longueur TCP, version mineure, type, drapeaux, drep, frag_length, auth_length, call_id, opnum."
tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -o dcerpc.desegment_dcerpc:FALSE \
    -Y 'dcerpc && tcp && !smb && !smb2 && !nbss' \
    -T fields -E separator='|' \
    -e frame.number -e tcp.len -e dcerpc.ver_minor -e dcerpc.pkt_type -e dcerpc.cn_flags \
    -e dcerpc.drep -e dcerpc.cn_frag_len -e dcerpc.cn_auth_len -e dcerpc.cn_call_id \
    -e dcerpc.opnum |
    LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
        # Une requete porte son opnum ; tshark le prete aussi a la reponse.
        { print capture, $1, $2, $3, $4, $5, $6, $7, $8, $9, ($4 == 0 && $10 != "" ? $10 : "-") }'
