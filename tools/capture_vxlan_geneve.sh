#!/usr/bin/env bash
# Capture VXLAN et Geneve reelles pour l'issue #15 : la regle du depot exige
# un golden test par tunnel sur une trame complete depuis Ethernet, et le
# corpus n'a aucune capture de ces deux encapsulations.
#
# Topologie, entierement locale et ephemere, rejouee pour chaque tunnel :
#
#   [ns pva]                              [ns pvb]
#    pv-a  10.99.0.1/24  --------------  pv-b  10.99.0.2/24     (underlay)
#    tnl0  192.168.42.1/24               tnl0  192.168.42.2/24  (overlay v4)
#          fd00:42::1/64                       fd00:42::2/64    (overlay v6)
#
# La capture se fait sur pv-a, cote underlay : on y voit les trames
# ENCAPSULEES — Ethernet / IPv4 / UDP 4789 ou 6081 / VXLAN ou Geneve /
# Ethernet interne / ARP, ICMP, NDP, ICMPv6. Capturer sur tnl0 montrerait le
# trafic deja decapsule, inutile pour le corpus.
#
# Usage :  sudo bash capture_vxlan_geneve.sh [dossier_de_sortie]
#
# Par defaut les fichiers sont ecrits dans pcaps_exemple/tunnels/{vxlan,geneve}
# du depot (deduit de l'emplacement du script) :
#   vxlan/vxlan_ping.pcapng   — VNI 42, port standard 4789
#   geneve/geneve_ping.pcapng — VNI 42, port standard 6081
#
# Ne touche a rien de permanent : namespaces et veth sont detruits en sortie,
# y compris en cas d'erreur ou d'interruption. Le module kernel geneve est
# charge automatiquement par `ip link add ... type geneve`.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_BASE="${1:-$REPO_DIR/pcaps_exemple/tunnels}"
NS_A="pva"
NS_B="pvb"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit tourner en root (ip netns add l'exige)." >&2
    echo "Usage : sudo bash $0 [dossier_de_sortie]" >&2
    exit 1
fi

for bin in dumpcap tshark; do
    command -v "$bin" >/dev/null || { echo "$bin manquant (paquet wireshark-common / tshark)." >&2; exit 1; }
done

cleanup_ns() {
    ip netns del "$NS_A" 2>/dev/null
    ip netns del "$NS_B" 2>/dev/null
}

cleanup() {
    cleanup_ns
    [ -n "${TMP_DIR:-}" ] && rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# dumpcap (separation de privileges) ne peut pas toujours ecrire dans le home
# de l'utilisateur : on capture dans un temporaire root-writable, puis on
# livre la copie finale en tant que l'utilisateur qui a lance sudo.
TMP_DIR="$(mktemp -d /tmp/capture_vxlan_geneve.XXXXXX)"
chmod 755 "$TMP_DIR"

# deliver <fichier_temporaire> <destination>
deliver() {
    local tmp="$1" out="$2"
    chmod 644 "$tmp" 2>/dev/null
    if [ -n "${SUDO_USER:-}" ]; then
        runuser -u "$SUDO_USER" -- cp "$tmp" "$out"
    else
        cp "$tmp" "$out"
    fi
}

# capture_tunnel <type> <port_udp> <fichier_de_sortie>
#
# Monte l'underlay et l'overlay, capture <port_udp> sur pv-a pendant que des
# pings v4 et v6 traversent l'overlay. Le premier ping v4 declenche un ARP
# interne, le premier v6 un Neighbor Solicitation interne : quatre familles
# de trames internes par capture (ARP, ICMP, NDP, ICMPv6), le protocol type
# du tunnel annoncant Ethernet dans tous les cas.
capture_tunnel() {
    local type="$1" port="$2" out="$3"

    echo "-- $type : creation des namespaces et de l'underlay"
    cleanup_ns 2>/dev/null   # repartir propre si un run precedent a laisse des restes
    ip netns add "$NS_A"
    ip netns add "$NS_B"

    ip link add pv-a type veth peer name pv-b
    ip link set pv-a netns "$NS_A"
    ip link set pv-b netns "$NS_B"

    ip netns exec "$NS_A" ip link set lo up
    ip netns exec "$NS_B" ip link set lo up
    ip netns exec "$NS_A" ip addr add 10.99.0.1/24 dev pv-a
    ip netns exec "$NS_B" ip addr add 10.99.0.2/24 dev pv-b
    ip netns exec "$NS_A" ip link set pv-a up
    ip netns exec "$NS_B" ip link set pv-b up

    echo "-- $type : tunnel VNI 42, port $port"
    case "$type" in
    vxlan)
        ip netns exec "$NS_A" ip link add tnl0 type vxlan id 42 \
            local 10.99.0.1 remote 10.99.0.2 dstport "$port" dev pv-a
        ip netns exec "$NS_B" ip link add tnl0 type vxlan id 42 \
            local 10.99.0.2 remote 10.99.0.1 dstport "$port" dev pv-b
        ;;
    geneve)
        ip netns exec "$NS_A" ip link add tnl0 type geneve id 42 \
            remote 10.99.0.2 dstport "$port"
        ip netns exec "$NS_B" ip link add tnl0 type geneve id 42 \
            remote 10.99.0.1 dstport "$port"
        ;;
    esac

    ip netns exec "$NS_A" ip addr add 192.168.42.1/24 dev tnl0
    ip netns exec "$NS_B" ip addr add 192.168.42.2/24 dev tnl0
    ip netns exec "$NS_A" ip -6 addr add fd00:42::1/64 dev tnl0 nodad
    ip netns exec "$NS_B" ip -6 addr add fd00:42::2/64 dev tnl0 nodad
    ip netns exec "$NS_A" ip link set tnl0 up
    ip netns exec "$NS_B" ip link set tnl0 up

    echo "-- $type : verification de l'underlay"
    ip netns exec "$NS_A" ping -c1 -W2 10.99.0.2 >/dev/null 2>&1 \
        && echo "   underlay ok" || { echo "   underlay KO" >&2; return 1; }

    echo "-- $type : capture sur pv-a pendant 8 s"
    local tmp="$TMP_DIR/$(basename "$out")"
    ip netns exec "$NS_A" dumpcap -i pv-a -f "udp port $port" -w "$tmp" \
        -a duration:8 -q &
    local dp=$!
    sleep 2

    ip netns exec "$NS_A" ping    -c3 -W2 192.168.42.2 >/dev/null 2>&1
    ip netns exec "$NS_A" ping -6 -c3 -W2 fd00:42::2   >/dev/null 2>&1

    wait "$dp"
    [ -s "$tmp" ] || { echo "   capture vide ou absente ($tmp)" >&2; return 1; }
    deliver "$tmp" "$out"

    echo
    echo "-- $type : contenu capture ($out)"
    tshark -r "$tmp" -T fields -e frame.number -e "$type.vni" \
        -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null
    echo
}

mkdir -p "$OUT_BASE/vxlan" "$OUT_BASE/geneve"

capture_tunnel vxlan  4789 "$OUT_BASE/vxlan/vxlan_ping.pcapng"
capture_tunnel geneve 6081 "$OUT_BASE/geneve/geneve_ping.pcapng"

echo "Attendu par capture : ARP, ICMP echo, NDP et ICMPv6 internes, tous"
echo "encapsules avec VNI 42, inner Ethernet. Extraire l'hex d'une trame :"
echo "  tshark -r <fichier> -x frame.number==N"
echo
echo "Penser a documenter la provenance (date, hote, ce script) dans un"
echo "README du sous-dossier, comme pour les autres captures du corpus."
