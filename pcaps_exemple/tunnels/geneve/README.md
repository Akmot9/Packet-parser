# Provenance — geneve_ping.pcapng

- Capture locale de Cyprien, **2026-08-24 09:26 (+0200)**, sur
  `erdtcyber-ThinkPad-P15-Gen-1`, generee par
  [`tools/capture_vxlan_geneve.sh`](../../../tools/capture_vxlan_geneve.sh)
  (issue #15).
- Topologie ephemere : deux network namespaces relies par un veth
  (underlay 10.99.0.0/24), tunnel **Geneve VNI 42, port standard 6081**
  (implementation kernel Linux, sans option TLV), overlay double pile
  192.168.42.0/24 + fd00:42::/64. Capture dumpcap sur le veth, cote encapsule.
- 30 trames, toutes `Ethernet / IPv4 / UDP 6081 / Geneve / Ethernet interne`
  (protocol type 0x6558). Trames notables pour les golden tests :
  - **10–11** : ARP interne (requete/reponse) ;
  - **12–13** : ICMP echo interne (requete/reponse) ;
  - **19–20** : NDP interne (Neighbor Solicitation/Advertisement) ;
  - **21** : ICMPv6 echo interne.
- Extraction de l'hex d'une trame :
  `tshark -r geneve_ping.pcapng -x frame.number==12`
