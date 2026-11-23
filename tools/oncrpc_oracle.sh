#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Regenere l'oracle tshark de tests/oncrpc_golden.rs (#381).
#
# Une ligne par message ONC RPC que tshark lit dans un datagramme UDP ou un
# segment TCP, dans pcaps_exemple/The-Ultimate-PCAP.pcapng et dans toutes
# les captures de pcaps_exemple/protocols/, quel que soit le port. Reglages :
# reassemblage TCP coupe (celui de TCP et les deux d'ONC RPC), analyse des
# numeros de sequence coupee. Chaque segment est lu seul, comme par la
# crate : d'un enregistrement plus long que son segment, tshark lit ce que
# le segment porte.
#
# tshark suit les echanges : dans une reponse, il recopie le programme, la
# version et la procedure de l'appel. La reponse ne les porte pas ; l'oracle
# ne les garde que pour un appel.
#
# Usage : tools/oncrpc_oracle.sh > tests/data/oncrpc_tshark_oracle.tsv
# Colonnes (tabulation, `-` si absent) : capture (chemin sous
# pcaps_exemple/), trame, rang du message dans la trame, transport, port
# source, port de destination, longueur capturee de la charge, longueur du
# fragment (TCP), dernier fragment (TCP), xid, type du message, programme,
# version, procedure, saveur et longueur de l'authentifiant, saveur et
# longueur du verifieur, etat de la reponse, etat d'acceptation, etat de
# refus, etat d'authentification.
set -euo pipefail

root="${1:-pcaps_exemple}"
echo "# Genere par tools/oncrpc_oracle.sh avec $(tshark --version | head -1) : un message ONC RPC par ligne."
echo "# Colonnes : capture, trame, rang, transport, port source, port de destination, longueur de la charge, longueur du fragment, dernier fragment, xid, type, programme, version, procedure, saveur de l'authentifiant, sa longueur, saveur du verifieur, sa longueur, etat de la reponse, etat d'acceptation, etat de refus, etat d'authentification."
{
    echo "$root/The-Ultimate-PCAP.pcapng"
    find "$root/protocols" -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) | LC_ALL=C sort
} | while IFS= read -r capture; do
    # skinny/wireshark_8805_packets.cap finit au milieu d'un enregistrement :
    # tshark lit tout puis sort en erreur.
    {
        tshark -r "$capture" -o tcp.desegment_tcp_streams:FALSE \
            -o rpc.desegment_rpc_over_tcp:FALSE -o rpc.defragment_rpc_over_tcp:FALSE \
            -o tcp.analyze_sequence_numbers:FALSE \
            -Y 'rpc.msgtyp && (udp || tcp) && !icmp' \
            -T json --no-duplicate-keys -J 'frame udp tcp rpc' 2>/dev/null ||
            [[ "$capture" == */wireshark_8805_packets.cap ]]
    } |
        python3 -I -c '
import json
import sys

capture = sys.argv[1]
text = sys.stdin.read().strip()
packets = json.loads(text) if text else []


def text_of(value):
    return "-" if value is None or isinstance(value, (dict, list)) else str(value)


def subtree(message, prefix):
    """Le sous-arbre dont le titre commence par `prefix`."""
    found = [value for key, value in message.items() if key.startswith(prefix)]
    if len(found) > 1:
        sys.exit(f"{capture} : plusieurs sous-arbres {prefix}")
    return found[0] if found else {}


def auth(message, prefix):
    tree = subtree(message, prefix)
    return text_of(tree.get("rpc.auth.flavor")), text_of(tree.get("rpc.auth.length"))


for packet in packets:
    layers = packet["_source"]["layers"]
    messages = layers["rpc"]
    if not isinstance(messages, list):
        messages = [messages]
    if "udp" in layers:
        transport, ports = "udp", layers["udp"]
        length = int(ports["udp.length"]) - 8
        source, destination = ports["udp.srcport"], ports["udp.dstport"]
    else:
        transport, ports = "tcp", layers["tcp"]
        length = int(ports["tcp.len"])
        source, destination = ports["tcp.srcport"], ports["tcp.dstport"]
    number = layers["frame"]["frame.number"]
    for rank, message in enumerate(messages):
        if "rpc.msgtyp" not in message:
            sys.exit(f"{capture} trame {number} : arbre inattendu {sorted(message)}")
        fragment = subtree(message, "Fragment header")
        is_call = message["rpc.msgtyp"] == "0"
        print(
            capture,
            number,
            rank,
            transport,
            source,
            destination,
            length,
            text_of(fragment.get("rpc.fraglen")),
            text_of(fragment.get("rpc.lastfrag")),
            int(message["rpc.xid"], 16),
            message["rpc.msgtyp"],
            text_of(message.get("rpc.program")) if is_call else "-",
            text_of(message.get("rpc.programversion")) if is_call else "-",
            text_of(message.get("rpc.procedure")) if is_call else "-",
            *(auth(message, "Credentials") if is_call else ("-", "-")),
            *auth(message, "Verifier"),
            text_of(message.get("rpc.replystat")),
            text_of(message.get("rpc.state_accept")),
            text_of(message.get("rpc.state_reject")),
            text_of(message.get("rpc.state_auth")),
            sep="\t",
        )
' "${capture#"$root"/}"
done
