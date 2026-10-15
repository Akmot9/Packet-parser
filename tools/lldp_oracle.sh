#!/usr/bin/env bash
# Regenere l'oracle tshark de tests/lldp_golden.rs.
#
# Une ligne par trame LLDP (tshark `lldp`) des captures passees en argument ;
# par defaut celles du corpus qui en portent : les deux captures PROFINET de
# protocols/profinet/ (commutateurs Siemens SCALANCE, automates SIMATIC) et,
# lue en place, The-Ultimate-PCAP.pcapng (commutateurs Cisco).
#
# Usage : tools/lldp_oracle.sh [capture...] > tests/data/lldp_tshark_oracle.tsv
# Colonnes (tabulation) : capture (chemin sous pcaps_exemple/protocols/),
# trame, types et longueurs des TLV (dans l'ordre, separes par des virgules),
# sous-type et identifiant du chassis (MAC, IP ou octets en hexadecimal),
# sous-type et identifiant du port (MAC, IP ou texte), TTL, nom de
# l'equipement, description du port, capacites et capacites activees,
# sous-types, adresses IPv4 et IPv6, sous-types et numeros d'interface des
# adresses de gestion, OUI des TLV d'organisation (decimaux) ; `-` pour un
# champ absent. Les descriptions de l'equipement ne sont pas reprises : tshark
# en echappe les retours a la ligne, leurs longueurs suffisent.
#
# Profil Wireshark vide : un Decode As ou une preference du poste qui
# regenere l'oracle ne doit rien changer.
set -euo pipefail

root="pcaps_exemple/protocols"
if [ "$#" -eq 0 ]; then
    set -- "$root/profinet/cisagov_profinet_io_cm_mixed_1.pcap" "$root/profinet/miguelob_pn.pcapng" \
        pcaps_exemple/The-Ultimate-PCAP.pcapng
fi
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT
export WIRESHARK_CONFIG_DIR="$profile"

echo "# Genere par tools/lldp_oracle.sh avec $(tshark --version | head -1) : une trame LLDP par ligne."
echo "# Colonnes : capture, trame, types et longueurs des TLV, chassis (sous-type, id), port (sous-type, id),"
echo "# TTL, nom, description du port, capacites, activees, adresses de gestion (sous-types, IPv4, IPv6,"
echo "# sous-types et numeros d'interface), OUI d'organisation."
for capture in "$@"; do
    case "$capture" in
        "$root"/*) name="${capture#"$root/"}" ;;
        pcaps_exemple/*) name="../${capture#pcaps_exemple/}" ;;
        *) name="$capture" ;;
    esac
    tshark -r "$capture" -Y "lldp" -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e lldp.tlv.type -e lldp.tlv.len \
        -e lldp.chassis.subtype -e lldp.chassis.id.mac -e lldp.chassis.id.ip4 -e lldp.chassis.id.ip6 \
        -e lldp.chassis.id -e lldp.port.subtype -e lldp.port.id.mac -e lldp.port.id.ip4 \
        -e lldp.port.id.ip6 -e lldp.port.id -e lldp.time_to_live -e lldp.tlv.system.name \
        -e lldp.port.desc -e lldp.tlv.system_cap -e lldp.tlv.enable_system_cap \
        -e lldp.mgn.address.subtype -e lldp.mgn.addr.ip4 -e lldp.mgn.addr.ip6 \
        -e lldp.mgn.interface.subtype -e lldp.mgn.interface.number -e lldp.orgtlv.oui |
        LC_ALL=C awk -F'|' -v OFS='\t' -v capture="$name" '
            function first(a, b, c, d) { return a != "" ? a : (b != "" ? b : (c != "" ? c : d)) }
            {
                chassis = first($5, $6, $7, $8)
                port = first($10, $11, $12, $13)
                for (i = 2; i <= 24; i++) if ($i == "") $i = "-"
                if (chassis == "") chassis = "-"
                if (port == "") port = "-"
                print capture, $1, $2, $3, $4, chassis, $9, port, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
            }'
done
