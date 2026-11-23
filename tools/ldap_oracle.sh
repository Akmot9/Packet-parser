#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/ldap_golden.rs (#372).
#
# Une ligne par segment TCP ou datagramme UDP que tshark dissèque comme
# LDAP (ou CLDAP, son nom sur UDP) dans pcaps_exemple/The-Ultimate-PCAP.pcapng
# et dans les captures de pcaps_exemple/protocols/ldap/. Trois reglages
# rendent tshark sans etat, comme la crate :
# - reassemblage TCP et LDAP coupes : chaque segment est lu seul ;
# - analyse des numeros de sequence coupee : sans elle, tshark ne passe pas
#   une retransmission a son dissecteur, et retrouve le debut d'un message
#   derriere la fin d'un autre.
#
# Usage : tools/ldap_oracle.sh > tests/data/ldap_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, transport, longueur de la charge,
# puis cinq listes separees par des virgules, `-` quand elles sont vides :
# longueurs des tampons SASL, identifiants de message, operations (numero de
# l'etiquette APPLICATION), codes de resultat hors liaison, codes de
# resultat des BindResponse (tshark les range dans un autre champ).
set -euo pipefail

echo "# Genere par tools/ldap_oracle.sh avec $(tshark --version | head -1) : un segment ou un datagramme LDAP par ligne."
echo "# Colonnes : capture, trame, transport, longueur de la charge, tampons SASL, identifiants, operations, codes de resultat, codes des BindResponse."
for capture in pcaps_exemple/The-Ultimate-PCAP.pcapng pcaps_exemple/protocols/ldap/*; do
    case "$capture" in *.pcap | *.pcapng | *.cap) ;; *) continue ;; esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -o ldap.desegment_ldap_messages:FALSE \
        -o tcp.analyze_sequence_numbers:FALSE \
        -Y 'ldap || cldap' -T fields -E separator='|' \
        -e frame.number -e tcp.len -e udp.length -e ldap.sasl_buffer_length \
        -e ldap.messageID -e ldap.protocolOp -e ldap.resultCode -e ldap.bindResponse_resultCode |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '
            function list(value) { return value == "" ? "-" : value }
            {
                # udp.length compte les huit octets de l en-tete UDP.
                if ($2 != "") { transport = "tcp"; size = $2 } else { transport = "udp"; size = $3 - 8 }
                print capture, $1, transport, size, list($4), list($5), list($6), list($7), list($8)
            }'
done
