#!/usr/bin/env bash
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
#
# Reproduit pcaps_exemple/protocols/java_rmi/jdk11-loopback.pcap : deux JVM
# echangent du Java RMI sur la boucle locale (tools/java_rmi_capture/), dumpcap
# capture les ports 1099, 50050 et 50051, editcap convertit en pcap (les
# metadonnees pcapng, systeme et interface, disparaissent).
#
# Usage : tools/java_rmi_capture.sh <sortie.pcap>
# Prerequis : JDK 11+, dumpcap autorise a capturer sur lo, editcap.
set -euo pipefail

out=${1:?usage: $0 <sortie.pcap>}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

javac -d "$work/classes" "$here/java_rmi_capture/JrmpCapture.java"
# Adresse annoncee dans les references distantes ; bail DGC court pour que
# le client renouvelle pendant la capture.
props=(-Djava.rmi.server.hostname=127.0.0.1 -Djava.rmi.dgc.leaseValue=4000)

dumpcap -q -i lo -f 'tcp port 1099 or tcp port 50050 or tcp port 50051' -w "$work/raw.pcapng" &
capture=$!
sleep 2

java "${props[@]}" -cp "$work/classes" JrmpCapture server 20 > "$work/server.log" &
server=$!
until grep -q pret "$work/server.log"; do sleep 0.2; done

java "${props[@]}" -cp "$work/classes" JrmpCapture client
java "${props[@]}" -cp "$work/classes" JrmpCapture raw
wait "$server" || true

sleep 1
kill -INT "$capture"
wait "$capture" || true
editcap -F pcap "$work/raw.pcapng" "$out"
