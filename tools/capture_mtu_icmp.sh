#!/usr/bin/env bash
# Capture ICMPv4 « fragmentation needed » (type 3 code 4) et ICMPv6 « packet
# too big » (type 2), les deux seuls cas ou rest_of_header porte une valeur
# non nulle : le MTU du lien suivant.
#
# Topologie, entierement locale et ephemere :
#
#   [root ns]            [ns ppr : routeur]              [ns ppd : cible]
#    pp-h  ------------  pp-r1        pp-r2  ----------  pp-d
#    10.0.1.1/24         10.0.1.2/24  10.0.2.1/24        10.0.2.2/24
#    fd00:1::1/64        fd00:1::2/64 fd00:2::1/64       fd00:2::2/64
#    MTU 1500            MTU 1500     MTU 1280           MTU 1280
#
# Le routeur recoit un paquet de 1428 octets (DF pose) et doit le faire sortir
# sur un lien a MTU 1280 : il repond ICMP frag-needed en annoncant 1280. En
# IPv6 les routeurs ne fragment jamais, d'ou un Packet Too Big.
#
# Usage :  sudo bash capture_mtu_icmp.sh [fichier_de_sortie.pcapng]
#
# Ne touche a rien de permanent : namespaces et veth sont detruits en sortie,
# y compris en cas d'erreur ou d'interruption.

set -uo pipefail

OUT="${1:-/tmp/icmp_mtu.pcapng}"
NS_R="ppr"
NS_D="ppd"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit tourner en root (ip netns add l'exige)." >&2
    echo "Usage : sudo bash $0 [sortie.pcapng]" >&2
    exit 1
fi

cleanup() {
    echo "-- nettoyage"
    ip netns del "$NS_R" 2>/dev/null
    ip netns del "$NS_D" 2>/dev/null
    ip link del pp-h 2>/dev/null
    ip link del pp-r2 2>/dev/null
}
trap cleanup EXIT INT TERM

# Repartir propre si un run precedent a laisse des restes.
cleanup 2>/dev/null

echo "-- creation des namespaces et des liens"
ip netns add "$NS_R"
ip netns add "$NS_D"

ip link add pp-h type veth peer name pp-r1
ip link add pp-r2 type veth peer name pp-d

ip link set pp-r1 netns "$NS_R"
ip link set pp-r2 netns "$NS_R"
ip link set pp-d  netns "$NS_D"

# --- cote hote -------------------------------------------------------------
ip addr add 10.0.1.1/24 dev pp-h
ip -6 addr add fd00:1::1/64 dev pp-h nodad
ip link set pp-h mtu 1500 up

# --- routeur ---------------------------------------------------------------
ip netns exec "$NS_R" ip link set lo up
ip netns exec "$NS_R" ip addr add 10.0.1.2/24 dev pp-r1
ip netns exec "$NS_R" ip -6 addr add fd00:1::2/64 dev pp-r1 nodad
ip netns exec "$NS_R" ip link set pp-r1 mtu 1500 up

ip netns exec "$NS_R" ip addr add 10.0.2.1/24 dev pp-r2
ip netns exec "$NS_R" ip -6 addr add fd00:2::1/64 dev pp-r2 nodad
# Le MTU reduit du lien de sortie : c'est lui qui declenche les deux messages.
ip netns exec "$NS_R" ip link set pp-r2 mtu 1280 up

ip netns exec "$NS_R" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$NS_R" sysctl -qw net.ipv6.conf.all.forwarding=1

# --- cible -----------------------------------------------------------------
ip netns exec "$NS_D" ip link set lo up
ip netns exec "$NS_D" ip addr add 10.0.2.2/24 dev pp-d
ip netns exec "$NS_D" ip -6 addr add fd00:2::2/64 dev pp-d nodad
ip netns exec "$NS_D" ip link set pp-d mtu 1280 up
ip netns exec "$NS_D" ip route add 10.0.1.0/24 via 10.0.2.1
ip netns exec "$NS_D" ip -6 route add fd00:1::/64 via fd00:2::1

# --- routes de l'hote vers le reseau distant -------------------------------
ip route add 10.0.2.0/24 via 10.0.1.2 dev pp-h
ip -6 route add fd00:2::/64 via fd00:1::2 dev pp-h

sleep 1

echo "-- verification de la connectivite (petits paquets, doivent passer)"
ping -c1 -W2 -s 56 10.0.2.2      >/dev/null 2>&1 && echo "   IPv4 ok" || echo "   IPv4 KO"
ping -6 -c1 -W2 -s 56 fd00:2::2  >/dev/null 2>&1 && echo "   IPv6 ok" || echo "   IPv6 KO"

echo "-- capture sur pp-h pendant 10 s"
dumpcap -i pp-h -f 'icmp or icmp6' -w "$OUT" -a duration:10 -q &
DP=$!
sleep 2

echo "-- envoi des gros paquets (1400 o de donnees, DF pose en IPv4)"
# Le cache PMTU retient la reponse : on vide d'abord pour garantir que le
# routeur emette bien l'ICMP a chaque execution du script.
ip route flush cache 2>/dev/null
ping -c2 -W2 -M do -s 1400 10.0.2.2     >/dev/null 2>&1
ping -6 -c2 -W2    -s 1400 fd00:2::2    >/dev/null 2>&1

wait $DP

# Rendre le fichier exploitable par l'utilisateur qui a lance sudo.
if [ -n "${SUDO_USER:-}" ]; then
    chown "$SUDO_USER" "$OUT" 2>/dev/null
fi
chmod 644 "$OUT" 2>/dev/null

echo
echo "-- contenu capture :"
tshark -r "$OUT" -T fields -e frame.number -e ip.src -e ipv6.src \
    -e icmp.type -e icmp.code -e icmp.mtu \
    -e icmpv6.type -e icmpv6.code -e icmpv6.mtu \
    -e _ws.col.Info 2>/dev/null

echo
echo "Fichier : $OUT"
echo "Attendu : ICMPv4 type 3 code 4 avec mtu=1280, et ICMPv6 type 2 avec mtu=1280."
