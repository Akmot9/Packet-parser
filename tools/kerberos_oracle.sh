#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/kerberos_golden.rs (#379).
#
# Une ligne par datagramme UDP ou segment TCP du port 88 ou tshark lit un
# message Kerberos, dans pcaps_exemple/The-Ultimate-PCAP.pcapng et dans
# toutes les captures de pcaps_exemple/protocols/. Reglages : reassemblage
# TCP coupe (celui de TCP et celui de Kerberos), analyse des numeros de
# sequence coupee. Chaque segment est lu seul, comme par la crate : d'un
# message plus long que son segment, tshark lit ce que le segment porte.
#
# tshark rend l'arbre du message en JSON ; le script Python en tire les
# champs par leur place dans l'arbre, pas par leur nom seul : le royaume
# d'un TGS-REQ est celui de son corps, pas celui du ticket que porte sa
# pre-authentification.
#
# Usage : tools/kerberos_oracle.sh > tests/data/kerberos_tshark_oracle.tsv
# Colonnes (tabulation, `-` si absent) : capture (chemin sous
# pcaps_exemple/), trame, transport, longueur capturee de la charge,
# longueur de l'enregistrement TCP, type du message, code d'erreur, royaume,
# royaume du client, type et composantes (separees par `/`) du nom du
# client, type et composantes du nom du service.
set -euo pipefail

root="${1:-pcaps_exemple}"
echo "# Genere par tools/kerberos_oracle.sh avec $(tshark --version | head -1) : un message Kerberos du port 88 par ligne."
echo "# Colonnes : capture, trame, transport, longueur de la charge, longueur de l'enregistrement, type, code d'erreur, royaume, royaume du client, type du nom du client, nom du client, type du nom du service, nom du service."
{
    echo "$root/The-Ultimate-PCAP.pcapng"
    find "$root/protocols" -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) | LC_ALL=C sort
} | while IFS= read -r capture; do
    # skinny/wireshark_8805_packets.cap finit au milieu d'un enregistrement :
    # tshark lit tout puis sort en erreur.
    {
        tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE -o kerberos.desegment:FALSE \
            -o tcp.analyze_sequence_numbers:FALSE \
            -Y 'kerberos.msg_type && (udp.port == 88 || tcp.port == 88)' \
            -T json --no-duplicate-keys -J 'frame udp tcp kerberos' 2>/dev/null ||
            [[ "$capture" == */wireshark_8805_packets.cap ]]
    } |
        python3 -I -c '
import json
import sys

capture = sys.argv[1]
text = sys.stdin.read().strip()
packets = json.loads(text) if text else []


def find(node, key):
    """Premiere valeur de la cle, en profondeur."""
    if isinstance(node, dict):
        if key in node:
            return node[key]
        for value in node.values():
            found = find(value, key)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = find(value, key)
            if found is not None:
                return found
    return None


def text_of(value):
    return "-" if value is None or isinstance(value, (dict, list)) else str(value)


def name(element, string_key):
    """Type et composantes d un PrincipalName."""
    if not isinstance(element, dict):
        return "-", "-"
    strings = find(element, string_key)
    if strings is None:
        strings = []
    elif not isinstance(strings, list):
        strings = [strings]
    return text_of(element.get("kerberos.name_type")), "/".join(strings) if strings else "-"


for packet in packets:
    layers = packet["_source"]["layers"]
    kerberos = layers["kerberos"]
    if isinstance(kerberos, list):
        sys.exit(f"{capture} : plusieurs messages dans une trame")
    tops = [key for key in kerberos if key.endswith("_element")]
    if len(tops) != 1:
        sys.exit(f"{capture} : arbre inattendu {sorted(kerberos)}")
    top = kerberos[tops[0]]
    if "udp" in layers:
        transport, length = "udp", int(layers["udp"]["udp.length"]) - 8
    else:
        transport, length = "tcp", int(layers["tcp"]["tcp.len"])
    kind = int(top["kerberos.msg_type"])
    if kind in (10, 12):
        body = top.get("kerberos.req_body_element") or {}
        realm, client_realm = body.get("kerberos.realm"), None
        client, service = body.get("kerberos.cname_element"), body.get("kerberos.sname_element")
    elif kind in (11, 13):
        ticket = top.get("kerberos.ticket_element") or {}
        realm, client_realm = ticket.get("kerberos.realm"), top.get("kerberos.crealm")
        client, service = top.get("kerberos.cname_element"), ticket.get("kerberos.sname_element")
    else:
        realm, client_realm = top.get("kerberos.realm"), top.get("kerberos.crealm")
        client, service = top.get("kerberos.cname_element"), top.get("kerberos.sname_element")
    print(
        capture,
        layers["frame"]["frame.number"],
        transport,
        length,
        text_of(find(kerberos, "kerberos.rm.length")),
        kind,
        text_of(top.get("kerberos.error_code")),
        text_of(realm),
        text_of(client_realm),
        *name(client, "kerberos.CNameString"),
        *name(service, "kerberos.SNameString"),
        sep="\t",
    )
' "${capture#"$root"/}"
done
