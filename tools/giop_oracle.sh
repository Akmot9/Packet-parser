#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/giop_tshark_regression.rs.
#
# Un message GIOP par ligne, tel que tshark le dissèque SANS reassemblage TCP
# (`tcp.desegment_tcp_streams:FALSE`) : c'est la vue d'un parseur stateless,
# ou un message qui deborde de son segment est vu dans son premier segment.
#
# Usage : tools/giop_oracle.sh [repertoire_de_captures] > tests/data/giop_tshark_oracle.tsv
# Colonnes : capture|trame|type|minor|flags|taille|request_id|reply_status|
#            locate_status|operation|exception_id|iiop_host|iiop_port|
#            longueur_object_key|longueur_stub_data|minor_code|completion_status
# Les deux dernieres colonnes sont des longueurs en octets (0 si absent) :
# tshark rend les octets en hexadecimal, ramenes ici a leur taille.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/giop}"
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap | *.dump) ;;
        *) continue ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -Y giop \
        -T fields -E separator='|' -E occurrence=f \
        -e frame.number -e giop.type -e giop.minor_version -e giop.flags \
        -e giop.len -e giop.request_id -e giop.replystatus -e giop.locale_status \
        -e giop.request_op -e giop.exceptionid -e giop.iiop.host -e giop.iiop.port \
        -e giop.objektkey_len -e giop.target_address.key_addr_len -e giop.stub_data \
        -e giop.minor_code_value -e giop.completion_status |
        LC_ALL=C awk -F'|' -v OFS='|' -v capture="$(basename "$capture")" '{
            # object_key : `objektkey_len` en GIOP 1.0/1.1 (et dans le profil
            # IIOP d un IOR), `key_addr_len` en 1.2.
            key = ($13 != "") ? $13 : $14
            stub = $15
            gsub(/:/, "", stub)
            # tshark rend litteralement `<MISSING>` un stub data vide.
            if (stub == "<MISSING>") stub = ""
            minor = $16; completion = $17
            NF = 12
            print capture, $0, key + 0, length(stub) / 2, minor, completion
        }'
done
