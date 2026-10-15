#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/wireguard_golden.rs.
#
# Une ligne par message WireGuard que tshark reconnait : heuristique `wg`,
# puis la conversation qu'elle epingle apres une Handshake Initiation, ou
# tshark accepte aussi des octets reserves non nuls (tshark n'enregistre
# WireGuard sur aucun port)
# dans les captures passees en argument, par defaut tout
# pcaps_exemple/protocols/wireguard/ — dont les datagrammes Zoom et League of
# Legends que l'heuristique prend a tort pour du WireGuard, nommes comme
# ecarts dans le golden.
#
# Usage : tools/wireguard_oracle.sh [capture...] > tests/data/wireguard_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, port source, port destination,
# longueur du message, type, octets reserves, index emetteur, index
# destinataire (0x%08x, petit-boutistes), compteur, cle ephemere, mac1, mac2,
# nonce, cookie chiffre (hexadecimal), keepalive (1) ; `-` pour un champ
# absent.
#
# Profil Wireshark vide et heuristique epinglee : un Decode As ou une
# preference du poste qui regenere l'oracle ne doit rien changer. Aucune
# cle : rien n'est dechiffre.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    set -- pcaps_exemple/protocols/wireguard/*.pcap*
fi
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT
export WIRESHARK_CONFIG_DIR="$profile"

echo "# Genere par tools/wireguard_oracle.sh avec $(tshark --version | head -1) : un message WireGuard par ligne."
echo "# Colonnes : capture, trame, port source, port destination, longueur, type, reserve, emetteur,"
echo "# destinataire, compteur, cle ephemere, mac1, mac2, nonce, cookie chiffre, keepalive."
for capture in "$@"; do
    tshark -r "$capture" --enable-heuristic wg -o wg.dissect_packet:FALSE -Y "wg" -T fields \
        -E separator='|' -E occurrence=f \
        -e frame.number -e udp.srcport -e udp.dstport -e udp.length -e wg.type -e wg.reserved \
        -e wg.sender -e wg.receiver -e wg.counter -e @wg.ephemeral -e wg.mac1 -e wg.mac2 \
        -e wg.nonce -e wg.encrypted_cookie -e wg.keepalive |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            $4 = $4 - 8
            gsub(":", "", $10)
            for (i = 2; i <= 15; i++) if ($i == "") $i = "-"
            print capture, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
        }'
done
