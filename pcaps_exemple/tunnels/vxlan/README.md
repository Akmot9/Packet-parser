# Provenance — vxlan_ping.pcapng

- Capture locale de Cyprien, **2026-08-24 09:26 (+0200)**, sur
  `erdtcyber-ThinkPad-P15-Gen-1`, generee par
  [`tools/capture_vxlan_geneve.sh`](../../../tools/capture_vxlan_geneve.sh)
  (issue #15).
- Topologie ephemere : deux network namespaces relies par un veth
  (underlay 10.99.0.0/24), tunnel **VXLAN VNI 42, port standard 4789**,
  overlay double pile 192.168.42.0/24 + fd00:42::/64. Capture dumpcap sur le
  veth, cote encapsule.
- 29 trames, toutes `Ethernet / IPv4 / UDP 4789 / VXLAN / Ethernet interne`.
  Trames notables pour les golden tests :
  - **9–10** : ARP interne (requete/reponse) ;
  - **11–12** : ICMP echo interne (requete/reponse) ;
  - **18–19** : NDP interne (Neighbor Solicitation/Advertisement) ;
  - **20** : ICMPv6 echo interne.
- Extraction de l'hex d'une trame :
  `tshark -r vxlan_ping.pcapng -x frame.number==11`
