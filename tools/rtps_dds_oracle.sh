#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/rtps_dds_golden.rs (#317) : la couche DDS
# des sous-messages DATA et DATA_FRAG RTPS.
#
# Une ligne par trame RTPS non fragmentee (comme tools/rtps_oracle.sh) qui
# porte au moins un parametre ou un en-tete d'encapsulation. tshark decode
# les QoS en ligne de tout DATA et DATA_FRAG, et en ParameterList les
# donnees des writers integres de la decouverte.
#
# Usage : tools/rtps_dds_oracle.sh [repertoire_de_captures] > tests/data/rtps_dds_tshark_oracle.tsv
# Colonnes (tabulation) : capture, trame, puis, chacune une liste separee
# par des points-virgules dans l'ordre du fil (`-` si vide) : identifiants
# d'encapsulation, parameterId (PID_SENTINEL compris), noms de topic, de
# type et d'entite, GUID de participant et d'endpoint, key hash, kind, port
# et adresse IPv4 des locators, status info, fiabilite, durabilite, ensemble
# des endpoints integres. Pas de domaine : le `rtps.domain_id` de tshark se
# deduit du port, pas du PID_DOMAIN_ID. `rtps.enable_topic_info` est coupe :
# sinon tshark ajoute aux donnees utilisateur le topic et le type qu'il a
# retenus de la decouverte, qui ne sont pas sur le fil.
set -euo pipefail

dir="${1:-pcaps_exemple/protocols/rtps}"
echo "# Genere par tools/rtps_dds_oracle.sh avec $(tshark --version | head -1) : une ligne par trame"
echo "# RTPS non fragmentee portant un parametre ou une encapsulation. Colonnes : capture, trame,"
echo "# encapsulations, PID, topics, types, entites, GUID participant, GUID endpoint, key hash,"
echo "# kind, port et IPv4 des locators, status info, fiabilite, durabilite, endpoints"
echo "# integres. Listes separees par des points-virgules, \`-\` si vide."
fields=(
    rtps.param.serialize.encap_kind rtps.param.id rtps.param.topicName rtps.param.typeName
    rtps.param.entityName rtps.param.participant_guid rtps.param.endpoint_guid rtps.guid
    rtps.locator.kind rtps.locator.port rtps.locator.ipv4
    rtps.param.status_info rtps.reliability_kind rtps.durability rtps.param.builtin_endpoint_set
)
for capture in "$dir"/*; do
    case "$capture" in
        *.pcap | *.pcapng | *.cap) ;;
        *) continue ;;
    esac
    args=()
    for field in "${fields[@]}"; do args+=(-e "$field"); done
    tshark -o rtps.enable_topic_info:FALSE -r "$capture" -Y 'rtps && !(ip.flags.mf == 1 || ip.frag_offset > 0)' \
        -T fields -E separator=$'\t' -E occurrence=a -E aggregator=';' \
        -e frame.number "${args[@]}" |
        LC_ALL=C awk -F'\t' -v OFS='\t' -v capture="$(basename "$capture")" '{
            if ($2 == "" && $3 == "") next
            for (i = 2; i <= NF; i++) if ($i == "") $i = "-"
            $1 = capture OFS $1
            print
        }'
done
