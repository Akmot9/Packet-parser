# TODO — Décapsulation des tunnels

Suivi du chantier « un paquet encapsulé → plusieurs niveaux de flux ».
Tout passe par le module [`src/parse/tunnel/mod.rs`](src/parse/tunnel/mod.rs).

> Suivi GitHub : [issue #15](https://github.com/Akmot9/Packet-parser/issues/15).

## ✅ Fait

- [x] Champ récursif `PacketFlow.inner: Option<Box<PacketFlow>>` + `flatten()`.
- [x] Refactor `parse_impl` → `parse_layers(data_link, depth)` (réutilisable).
- [x] Garde-fou profondeur (`MAX_TUNNEL_DEPTH = 4`) + dégradation gracieuse
      (jamais d'erreur : `None` → seule la ligne externe est produite).
- [x] **CAPWAP-Data** (UDP 5247) → **IEEE 802.11** (ToDS/FromDS/WDS/QoS, gestion
      du byte-swap Frame Control Cisco) → **LLC/SNAP** → L3.
- [x] Le tunnel est reporté comme protocole applicatif de la ligne externe
      (ex. `"CAPWAP"`).
- [x] 2 tests de référence sur trames réelles (ToDS/HLEN 16 et FromDS/HLEN 8).

---

## 🧭 Rappel : comment brancher un nouveau tunnel

Dans `detect_inner()` : reconnaître le tunnel, peler ses en-têtes, obtenir la
trame interne, puis appeler `PacketFlow::parse_layers(inner_dl, depth + 1)` et
renvoyer `Some(("NOM", inner))`.

Deux formes de trame interne :

- **Interne = Ethernet** (VXLAN, NVGRE, Geneve-transparent) : la trame interne
  commence par un en-tête Ethernet complet →
  `PacketFlow::parse_layers(DataLink::try_from(inner_bytes)?, depth + 1)`.
- **Interne = IP brute** (IP-in-IP, GTP-U, GRE-IP) : pas de L2 interne →
  synthétiser un `DataLink` à MAC vides (`MacAddress([0u8; 6])`), `ethertype`
  = IPv4 (`0x0800`) ou IPv6 (`0x86DD`), `payload` = octets IP internes, puis
  `parse_layers`.

### ⚠️ Point d'architecture à ne pas rater

`detect_inner()` n'est appelé aujourd'hui **que si `transport` est `Some`**
(donc pour les tunnels au-dessus d'UDP/TCP). Les tunnels **niveau IP**
(GRE = proto 47, IP-in-IP = 4/41) ne produisent **pas** de couche `Transport`
→ il faudra ajouter un point de détection dans `parse_layers` quand
`transport` est `None` mais que `internet.payload_protocol` vaut Gre/Ipip.
Prévoir de passer `internet` (ou son `payload` + `payload_protocol`) à la
détection, pas seulement `transport`.

---

## 📋 À faire (un test de référence par tunnel = obligatoire)

> Ne rien merger sans une trame réelle en fixture (golden test), comme pour
> CAPWAP. Fournir le hex complet depuis l'Ethernet.

### Tunnels UDP (hook `transport` existant — le plus simple)

- [x] **VXLAN** — UDP 4789. En-tête 8 octets, seul le bit I accepté (GBP/GPE
      refusés). Interne = **Ethernet**. Golden sur les trames 9/11/20 de
      `pcaps_exemple/tunnels/vxlan/vxlan_ping.pcapng` (capture locale,
      `tools/capture_vxlan_geneve.sh`).
- [ ] **GTP-U** — UDP 2152. En-tête variable (min 8 octets ; +4 si un des flags
      E/S/PN est posé ; puis extension headers). Interne = **IP** (pas de L2).
      Attention au champ « message type » = 255 (G-PDU) pour ne peler que les
      données. Fixture requise — aucune capture disponible (équipement ou
      outil userspace nécessaire).
- [x] **Geneve** — UDP 6081. En-tête 8 octets + options sautées (Opt Len en
      mots de 4), OAM refusé. `protocol type` : Ethernet (0x6558) ou IP.
      Golden sur les trames 10/12/21 de
      `pcaps_exemple/tunnels/geneve/geneve_ping.pcapng` (capture locale).

### Tunnels niveau IP (hook `detect_inner_l3`, livré en 10.4.0)

- [x] **IP-in-IP** — IP proto 4 (IPv4) / 41 (IPv6). Interne = **IP** directe,
      version vérifiée contre l'annonce du protocole externe. Golden sur
      The-Ultimate-PCAP (livré en 10.4.0, commit 583a7d8).
- [x] **GRE** — IP proto 47. v0 avec options C/K/S ; `protocol type` : IP
      (0x0800/0x86DD) ou **Ethernet** (0x6558). ERSPAN, v1 (PPTP) et
      keepalives refusés. Golden sur The-Ultimate-PCAP dont un GRE-dans-GRE
      (livré en 10.4.0, commit 583a7d8).

### Cas particuliers / hors périmètre immédiat

- [ ] **CAPWAP-DTLS** (préambule type 1) : chiffré → **non décapsulable**.
      Déjà géré : on renvoie `None` (pas de récursion), la ligne externe reste.
      À documenter comme limite, rien à coder.
- [ ] **ESP** (proto 50) : chiffré → idem, ne pas récurser.
- [ ] **MPLS** (EtherType 0x8847/0x8848) : encapsulation niveau 2.5, à traiter
      au niveau `DataLink` si besoin un jour.

---

## 🔗 Intégration Sonar (fait côté Sonar par Cyprien)

- [ ] Re-vendorer la crate dans Sonar (`cargo vendor`) après bump de version.
- [ ] Dans le pipeline de capture, itérer `flatten()` → **N lignes de flux par
      paquet**.
- [ ] **Attribution des octets par niveau** pour ne pas doubler le volume :
      ligne externe = taille de la trame complète ; ligne interne = taille du
      segment interne (`inner.data_link.payload.len()` pour la couche L3
      interne). Le `count` (paquets) à +1 par niveau est correct.

---

## 🧪 Rappel tests

- Décoder la trame en amont (Python/Wireshark) pour figer les offsets et les
  adresses attendues, puis asserter externe **et** interne + `flatten().len()`.
- Couvrir les variantes qui changent le pelage (longueurs d'en-tête, sens du
  flux, présence d'options), comme les deux tests CAPWAP ToDS/FromDS.
