#!/usr/bin/env bash
# Recette reproductible des captures GIOP du labo (pcaps_exemple/protocols/giop/lab_*.pcap).
#
# Un vrai ORB (omniORB 4.3, paquets Debian trixie) tourne dans un conteneur
# ephemere : un serveur et une serie de clients, chacun provoquant un type de
# message ou de statut GIOP que les captures publiques ne couvrent pas. Tout
# passe par le loopback du conteneur, capture par tcpdump. Aucun octet n'est
# fabrique a la main, a une exception pres, documentee dans garbage.py : le
# stimulus tronque qui provoque le MessageError du serveur.
#
# Usage : tools/capture_giop.sh [repertoire_de_sortie]
# Prerequis : docker.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$(mkdir -p "${1:-$here/../pcaps_exemple/protocols/giop}" && cd "${1:-$here/../pcaps_exemple/protocols/giop}" && pwd)"

docker run --rm -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$here/giop_lab:/src:ro" -v "$out:/out" debian:trixie bash -euc '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq g++ libomniorb4-dev omniidl tcpdump python3-minimal >/dev/null 2>&1
dpkg -l | awk "/omniorb|omniidl/ {print \"# \" \$2, \$3}"

mkdir -p /lab && cd /lab
cp /src/* .
omniidl -bcxx lab.idl
g++ -O1 -o server server.cc labSK.cc -lomniORB4 -lomnithread
g++ -O1 -o client client.cc labSK.cc -lomniORB4 -lomnithread

PORT=12809
capture() { # capture <nom> <commande...>
    local name="$1"; shift
    tcpdump -i lo -U -w "/out/lab_$name.pcap" "tcp port $PORT" 2>/dev/null &
    local dump=$!
    sleep 1
    "$@" || true
    sleep 1
    kill -INT "$dump"; wait "$dump" 2>/dev/null || true
    chown "$HOST_UID:$HOST_GID" "/out/lab_$name.pcap"
    chmod 644 "/out/lab_$name.pcap"
}

# Scan des connexions entrantes oisives toutes les 2 s : CloseConnection.
./server -ORBendPoint "giop:tcp:127.0.0.1:$PORT" \
    -ORBinConScanPeriod 2 -ORBscanGranularity 1 &
server=$!
for _ in $(seq 50); do [ -s /lab/ghost.ior ] && break; sleep 0.1; done

capture giop12_basic    ./client basic
capture giop11_basic    ./client basic -ORBmaxGIOPVersion 1.1
capture giop10_basic    ./client basic -ORBmaxGIOPVersion 1.0
capture system_exception ./client ghost
# Timeout client : omniORB abandonne l appel sans emettre de CancelRequest
# (constat du 2026-09-19), la capture garde le Request sans Reply.
capture client_timeout  ./client timeout -ORBclientCallTimeOutPeriod 500
capture close_connection ./client idle -ORBoutConScanPeriod 0
capture message_error   python3 garbage.py "$PORT"

kill "$server" 2>/dev/null || true
'
ls -la "$out"/lab_*.pcap
