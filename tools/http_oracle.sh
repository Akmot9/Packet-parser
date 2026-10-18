#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/http_golden.rs (#176).
#
# Une ligne par trame qui porte une requete ou une reponse HTTP/1.x que
# tshark dissèque SANS reassemblage TCP (`tcp.desegment_tcp_streams:FALSE`),
# hors retransmissions (que tshark ne dissèque pas) et hors HTTP dechiffre
# dans TLS (`tls12-dsb.pcapng`, cle dans le fichier : la crate voit du TLS).
# Un parseur sans etat ne voit que ce qui tient dans le segment.
#
# Usage : tools/http_oracle.sh [captures...] > tests/data/http_tshark_oracle.tsv
# Sans argument : pcaps_exemple/protocols (recursif) et
# pcaps_exemple/The-Ultimate-PCAP.pcapng.
# Colonnes (tabulation) : capture, trame, genre (request | response |
# retransmission), version, methode ou code, URI ou phrase (premier message
# du segment ; `-` si vide). Les retransmissions TCP a payload sont listees
# telles quelles, sans dissection : tshark ne les dissèque pas, la crate,
# sans etat, les voit comme les autres segments — le test les ecarte de la
# comparaison. `http-on-port-5432.pcap` (negatif PostgreSQL de Zeek) est
# dissequee avec « Decode As » HTTP sur 5432, ce que la sonde aveugle de la
# crate fait d'elle-meme.
set -euo pipefail

if [ "$#" -gt 0 ]; then
    captures=("$@")
else
    mapfile -t captures < <(find pcaps_exemple/protocols -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) | sort)
    captures+=(pcaps_exemple/The-Ultimate-PCAP.pcapng)
fi
echo "# Genere par tools/http_oracle.sh avec $(tshark --version | head -1) : une ligne par trame HTTP/1.x,"
echo "# sans reassemblage TCP, hors retransmissions et hors HTTP dechiffre dans TLS. Colonnes :"
echo "# capture, trame, genre (request | response), version, methode ou code, URI ou phrase"
echo "# (premier message du segment ; \`-\` si vide)."
for capture in "${captures[@]}"; do
    decode_as=()
    case "$(basename "$capture")" in
        http-on-port-5432.pcap) decode_as=(-d tcp.port==5432,http) ;;
    esac
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE \
        -Y 'tcp.analysis.retransmission && tcp.len > 0' -T fields -e frame.number 2>/dev/null |
        LC_ALL=C awk -v OFS='\t' -v capture="$(basename "$capture")" '{ print capture, $1, "retransmission", "-", "-", "-" }'
    tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE "${decode_as[@]}" \
        -Y 'http && !tls && !tcp.analysis.retransmission && (http.request || http.response)' \
        -T fields -E separator='|' -E occurrence=f \
        -e frame.number -e http.request -e http.response \
        -e http.request.method -e http.request.uri -e http.request.version \
        -e http.response.version -e http.response.code -e http.response.phrase 2>/dev/null |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$(basename "$capture")" '{
            if (($2 == "1" || $2 == "True") && ($3 == "1" || $3 == "True")) kind = "both"
            else if ($2 == "1" || $2 == "True") kind = "request"
            else kind = "response"
            if (kind == "request") { version = $6; what = $4; detail = $5 }
            else { version = $7; what = $8; detail = $9 }
            if (version == "") version = "-"
            if (what == "") what = "-"
            if (detail == "") detail = "-"
            print capture, $1, kind, version, what, detail
        }'
done
