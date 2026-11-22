#!/usr/bin/env python3
# Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
#
# Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
# This file may not be copied, modified, or distributed except according to those terms.
"""Censure une capture privee pour la verser dans le depot public.

Entree : un pcap classique, Ethernet, deja reduit aux trames utiles, par
exemple avec `tshark -r terrain.pcapng -Y '<filtre>' -F pcap -w extrait.pcap`.
Sortie : un pcap classique ou ne restent que la forme des trames et les
octets d'en-tete du protocole applicatif vise.

Ce qui est reecrit :
  - horodatages : la premiere trame part de l'epoque 0, les ecarts sont gardes ;
  - adresses MAC : 02:00:00:00:00:NN, dans l'ordre de premiere apparition ;
  - identifiant de VLAN : 1, 2, 3... dans l'ordre de premiere apparition ;
  - adresses IPv4 : 192.0.2.N (TEST-NET-1, RFC 5737) ;
  - ports >= 1024 : 50000, 50001... dans l'ordre de premiere apparition ;
  - sommes de controle IPv4, TCP et UDP : recalculees ;
  - charge applicative : tout octet hors des plages que `--proto` declare
    structurelles est remplace (0x00, ou 'x' dans une chaine) ;
  - bourrage Ethernet apres le datagramme IP : mis a zero.

Les trames qui ne sont pas IPv4 + TCP ou UDP, et les fragments IP, sont
ecartes : le script refuse de recopier ce qu'il ne sait pas relire.

`--check` relit la sortie et echoue si une adresse MAC, une adresse IPv4 ou
un port d'origine y figure encore a sa place d'en-tete.
"""

import argparse
import struct
import sys

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = (0x8100, 0x88A8)
FIRST_PORT = 50000


def read_pcap(path):
    with open(path, "rb") as handle:
        data = handle.read()
    endian = PCAP_MAGICS.get(data[:4])
    if endian is None:
        sys.exit(f"{path} : pas un pcap classique (convertir avec -F pcap)")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != LINKTYPE_ETHERNET:
        sys.exit(f"{path} : type de lien {linktype}, seul Ethernet est gere")
    frames, offset = [], 24
    while offset + 16 <= len(data):
        sec, frac, caplen, origlen = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        frames.append((sec, frac, origlen, data[offset : offset + caplen]))
        offset += caplen
    return data[:4], endian, frames


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def varint(data, offset):
    """Entier a longueur variable de [MC-NMF] : 7 bits par octet, 5 octets max."""
    value = 0
    for index in range(5):
        if offset + index >= len(data):
            return None
        byte = data[offset + index]
        value |= (byte & 0x7F) << (7 * index)
        if byte & 0x80 == 0:
            return value, index + 1
    return None


NBFSE_ENVELOPE = b"\x56\x02\x0b\x01\x73\x04"


def nbfse_layout(payload, start):
    """Decoupe l'amorce [MC-NBFSE] d'une enveloppe qui commence a `start`.

    Rend (plages a garder, plages de chaines a remplacer), ou None si la
    table de chaines ne tient pas dans le segment ou n'est pas suivie de
    s:Envelope / s:Header du dictionnaire statique."""
    size = varint(payload, start)
    if size is None:
        return None
    table, width = size
    cursor = start + width
    end = cursor + table
    keep, strings = [(start, cursor)], []
    while cursor < end:
        entry = varint(payload, cursor)
        if entry is None:
            return None
        length, entry_width = entry
        keep.append((cursor, cursor + entry_width))
        strings.append((cursor + entry_width, cursor + entry_width + length))
        cursor += entry_width + length
    if cursor != end or payload[end : end + 6] != NBFSE_ENVELOPE:
        return None
    keep.append((end, end + 6))
    return keep, strings


def nmf_record_starts(payload, offset):
    """Vrai si un enregistrement [MC-NMF] reconnaissable commence ici.

    Un segment TCP de suite commence au milieu d'une enveloppe : ses
    premiers octets sont du contenu, pas un type d'enregistrement. Seules
    les formes sans ambiguite sont donc acceptees ; le reste est efface."""
    kind = payload[offset]
    if kind == 0x00:  # Version 1.0 suivie de Mode
        return payload[offset : offset + 4] == b"\x00\x01\x00\x01"
    if kind in (0x05, 0x06):  # enveloppe [MC-NBFSE]
        size = varint(payload, offset + 1)
        if size is None:
            return False
        return nbfse_layout(payload, offset + 1 + size[1]) is not None
    if kind in (0x07, 0x0A, 0x0B, 0x0C):  # un octet, seul ou en fin de segment
        return offset == len(payload) - 1
    return False


def scrub_nmf(payload):
    """Garde les types d'enregistrement, les longueurs et l'amorce
    [MC-NBFSE] d'une enveloppe ; remplace URI, chaines et corps."""
    out = bytearray(len(payload))
    offset = 0
    preamble = False
    while offset < len(payload):
        if not preamble and not nmf_record_starts(payload, offset):
            break
        kind = payload[offset]
        if kind == 0x00 and offset + 3 <= len(payload):  # Version
            out[offset : offset + 3] = payload[offset : offset + 3]
            offset += 3
            preamble = True
        elif kind in (0x01, 0x03) and offset + 2 <= len(payload):  # Mode, Known Encoding
            out[offset : offset + 2] = payload[offset : offset + 2]
            offset += 2
        elif kind in (0x07, 0x0A, 0x0B, 0x0C):  # End, Upgrade Response, Ack, Preamble End
            out[offset] = kind
            offset += 1
            preamble = False
        elif kind in (0x02, 0x04, 0x09):  # chaines : Via, encodage, upgrade
            size = varint(payload, offset + 1)
            if size is None:
                break
            length, width = size
            start = offset + 1 + width
            out[offset:start] = payload[offset:start]
            end = min(start + length, len(payload))
            text = b"net.tcp://host/" if kind == 0x02 else b""
            out[start:end] = (text + b"x" * length)[: end - start]
            offset = start + length
        elif kind in (0x05, 0x06):  # enveloppes
            length, width = varint(payload, offset + 1)
            start = offset + 1 + width
            out[offset:start] = payload[offset:start]
            keep, strings = nbfse_layout(payload, start)
            for low, high in keep:
                out[low:high] = payload[low:high]
            for low, high in strings:
                out[low:high] = b"x" * (high - low)
            offset = start + length
        else:
            break
    return bytes(out)


def scrub_rtp(payload):
    """Garde l'en-tete RTP (fixe, CSRC, extension) ; efface la charge."""
    if len(payload) < 12 or payload[0] >> 6 != 2:
        return bytes(len(payload))
    keep = 12 + 4 * (payload[0] & 0x0F)
    if payload[0] & 0x10 and keep + 4 <= len(payload):
        keep += 4 + 4 * struct.unpack("!H", payload[keep + 2 : keep + 4])[0]
    keep = min(keep, len(payload))
    out = bytearray(len(payload))
    out[:keep] = payload[:keep]
    # Le bit de bourrage reste : son dernier octet donne la longueur.
    if payload[0] & 0x20 and len(payload) > keep:
        out[-1] = payload[-1]
    return bytes(out)


def scrub_rtcp(payload):
    """Garde les en-tetes, les SSRC, les compteurs et les blocs de rapport ;
    efface l'horodatage NTP d'un SR, les LSR, le texte des items SDES, la
    raison d'un BYE et le contenu d'un APP ou d'un XR."""
    out = bytearray(len(payload))
    offset = 0
    while offset + 4 <= len(payload):
        first, kind = payload[offset], payload[offset + 1]
        length = (struct.unpack("!H", payload[offset + 2 : offset + 4])[0] + 1) * 4
        end = offset + length
        if first >> 6 != 2 or not 200 <= kind <= 207 or end > len(payload):
            return bytes(len(payload))
        count = first & 0x1F
        packet = bytearray(payload[offset:end])
        if kind in (200, 201):
            blocks = 28 if kind == 200 else 8
            if kind == 200:
                packet[8:16] = bytes(8)  # horodatage NTP
            for index in range(count):
                lsr = blocks + 24 * index + 16
                packet[lsr : lsr + 4] = bytes(4)
            packet[blocks + 24 * count :] = bytes(max(0, length - blocks - 24 * count))
        elif kind == 202:
            cursor = 4
            for _ in range(count):
                cursor += 4  # SSRC du morceau
                while cursor < length and packet[cursor] != 0:
                    size = packet[cursor + 1]
                    packet[cursor + 2 : cursor + 2 + size] = b"x" * size
                    cursor += 2 + size
                cursor = (cursor // 4 + 1) * 4  # item nul, puis alignement
        elif kind == 203:
            packet[4 + 4 * count :] = bytes(max(0, length - 4 - 4 * count))
        elif kind in (204, 207):
            packet[8:] = bytes(max(0, length - 8))
        out[offset:end] = packet[:length]
        offset = end
    if offset != len(payload):
        return bytes(len(payload))
    return bytes(out)


SCRUBBERS = {"nmf": scrub_nmf, "rtcp": scrub_rtcp, "rtp": scrub_rtp}


class Censor:
    def __init__(self, scrub):
        self.scrub = scrub
        self.macs, self.vlans, self.ips, self.ports = {}, {}, {}, {}

    def mac(self, raw):
        if raw == b"\xff" * 6:
            return raw
        if raw not in self.macs:
            self.macs[raw] = b"\x02\x00\x00\x00" + struct.pack("!H", len(self.macs) + 1)
        return self.macs[raw]

    def ip(self, raw):
        if raw not in self.ips:
            if len(self.ips) >= 254:
                sys.exit("plus de 254 adresses IPv4 : reduire l'extrait")
            self.ips[raw] = bytes([192, 0, 2, len(self.ips) + 1])
        return self.ips[raw]

    def port(self, value):
        if value < 1024:
            return value
        if value not in self.ports:
            self.ports[value] = FIRST_PORT + len(self.ports)
        return self.ports[value]

    def frame(self, raw):
        """Rend la trame censuree, ou None si elle doit etre ecartee."""
        if len(raw) < 14:
            return None
        out = bytearray(self.mac(raw[0:6]) + self.mac(raw[6:12]))
        offset = 12
        ethertype = struct.unpack("!H", raw[offset : offset + 2])[0]
        while ethertype in ETHERTYPE_VLAN:
            if offset + 6 > len(raw):
                return None
            tci = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
            vid = tci & 0x0FFF
            self.vlans.setdefault(vid, len(self.vlans) + 1)
            out += struct.pack("!HH", ethertype, (tci & 0xF000) | self.vlans[vid])
            offset += 4
            ethertype = struct.unpack("!H", raw[offset : offset + 2])[0]
        if ethertype != ETHERTYPE_IPV4:
            return None
        out += struct.pack("!H", ethertype)
        offset += 2

        ip = raw[offset:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return None
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        fragment = struct.unpack("!H", ip[6:8])[0]
        protocol = ip[9]
        if ihl != 20 or fragment & 0x3FFF or total > len(ip) or total < ihl:
            return None
        src, dst = self.ip(ip[12:16]), self.ip(ip[16:20])
        header = bytearray(ip[:20])
        header[10:12] = b"\x00\x00"
        header[12:16], header[16:20] = src, dst
        header[10:12] = struct.pack("!H", checksum(bytes(header)))

        segment = ip[ihl:total]
        if protocol == 6:
            if len(segment) < 20:
                return None
            data_offset = (segment[12] >> 4) * 4
            if data_offset < 20 or data_offset > len(segment):
                return None
            l4 = bytearray(segment[:data_offset])
            checksum_at = 16
        elif protocol == 17:
            if len(segment) < 8:
                return None
            data_offset = 8
            l4 = bytearray(segment[:8])
            checksum_at = 6
        else:
            return None
        sport, dport = struct.unpack("!HH", segment[0:4])
        l4[0:4] = struct.pack("!HH", self.port(sport), self.port(dport))
        l4[checksum_at : checksum_at + 2] = b"\x00\x00"
        payload = self.scrub(segment[data_offset:])
        pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(l4) + len(payload))
        value = checksum(pseudo + bytes(l4) + payload)
        if protocol == 17 and value == 0:
            value = 0xFFFF
        l4[checksum_at : checksum_at + 2] = struct.pack("!H", value)

        out += header + l4 + payload
        out += bytes(len(raw) - offset - total)  # bourrage Ethernet
        return bytes(out)


def check(censor, frames):
    """Aucune valeur d'origine ne doit rester a sa place d'en-tete."""
    originals = set(censor.macs) | set(censor.ips)
    replaced = set(censor.macs.values()) | set(censor.ips.values())
    leaks = 0
    for raw in frames:
        for secret in originals - replaced:
            if secret in raw:
                leaks += 1
    return leaks


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--proto", choices=sorted(SCRUBBERS), required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    magic, endian, frames = read_pcap(args.source)
    censor = Censor(SCRUBBERS[args.proto])
    kept, dropped = [], 0
    for sec, frac, _origlen, raw in frames:
        censored = censor.frame(raw)
        if censored is None:
            dropped += 1
        else:
            kept.append((sec, frac, censored))
    if not kept:
        sys.exit("aucune trame gardee")

    unit = 1_000_000_000 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1_000_000
    origin = kept[0][0] * unit + kept[0][1]
    with open(args.destination, "wb") as handle:
        handle.write(magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, 262144, 1))
        for sec, frac, raw in kept:
            delta = sec * unit + frac - origin
            handle.write(
                struct.pack(endian + "IIII", delta // unit, delta % unit, len(raw), len(raw))
            )
            handle.write(raw)

    print(
        f"{len(kept)} trame(s) gardee(s), {dropped} ecartee(s) ; "
        f"{len(censor.macs)} MAC, {len(censor.ips)} IPv4, "
        f"{len(censor.ports)} port(s), {len(censor.vlans)} VLAN reecrits"
    )
    if args.check:
        leaks = check(censor, [raw for _, _, raw in kept])
        if leaks:
            sys.exit(f"ECHEC : {leaks} valeur(s) d'origine encore presente(s)")
        print("verification : aucune adresse d'origine dans la sortie")


if __name__ == "__main__":
    main()
