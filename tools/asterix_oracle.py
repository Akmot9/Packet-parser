#!/usr/bin/env python3
"""Regenere l'oracle tshark des golden tests ASTERIX (tests/asterix_golden.rs).

Pour chaque trame qu'un dissecteur ASTERIX force sur les ports indiques
decode, la forme des data blocks telle que `tshark -V` la dissèque :
`CAT:LEN:items/longueur;items/longueur|CAT:LEN:...` — un data block par `|`,
un record par `;`, les data items par `,` (suffixe de l'identifiant : `010`,
`RE`, `SP`), puis `/` et la longueur du record en octets, FSPEC compris.

Les trames de meme forme sont regroupees : une ligne par forme et par
capture, avec la liste des trames (`1-4,9` : plages et numeros).

Usage :
    tools/asterix_oracle.py <capture> <ports> [<capture> <ports> ...]
        > tests/data/asterix_tshark_oracle.tsv
    <ports> : `8600`, `8611-8612` ou `6001-6011;20101-20104` (un `-d` par
    plage, separees par `;`).

Les trames que tshark declare malformees (`[Malformed Packet: ASTERIX]`)
vont sur la sortie d'erreur, meme format, prefixees par `MALFORMED` : a
examiner une par une avant de les figer ailleurs (voir SOURCE.md).
"""
import os
import re
import subprocess
import sys

RE_PACKET = re.compile(r"^ASTERIX packet, Category (\d+)")
RE_LENGTH = re.compile(r"^    Length: (\d+)")
RE_MESSAGE = re.compile(r"^    Asterix message, #(\d+), length: (\d+)")
RE_ITEM = re.compile(r"^        ([0-9A-Z]{2,3}), ")
RE_FRAME = re.compile(r"^Frame (\d+): ")
RE_MALFORMED = re.compile(r"\[Malformed Packet")


def ranges(frames):
    """`[1, 2, 3, 5]` -> `1-3,5`."""
    out = []
    start = prev = None
    for frame in frames:
        if start is None:
            start = prev = frame
        elif frame == prev + 1:
            prev = frame
        else:
            out.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = frame
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(out)


def dissect(capture, ports):
    """Rend {trame: (forme, malformee)} pour les trames ASTERIX de la capture."""
    cmd = ["tshark", "-r", capture]
    for port_range in ports.split(";"):
        cmd += ["-d", f"udp.port=={port_range},asterix"]
    cmd += ["-Y", "asterix", "-V"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20
    )
    shapes = {}
    frame = None
    blocks = []
    malformed = False
    in_asterix = False

    def flush():
        if frame is None:
            return
        shape = "|".join(
            f"{cat}:{length}:"
            + ";".join(",".join(items) + f"/{record_len}" for items, record_len in records)
            for cat, length, records in blocks
        )
        shapes[frame] = (shape, malformed)

    for line in proc.stdout:
        match = RE_FRAME.match(line)
        if match:
            flush()
            frame = int(match.group(1))
            blocks = []
            malformed = False
            in_asterix = False
            continue
        if line.startswith("ASTERIX packet"):
            in_asterix = True
            blocks.append([int(RE_PACKET.match(line).group(1)), None, []])
            continue
        if RE_MALFORMED.search(line):
            malformed = True
            continue
        if not in_asterix:
            continue
        if line.startswith("    Length: ") and blocks and blocks[-1][1] is None:
            blocks[-1][1] = int(RE_LENGTH.match(line).group(1))
            continue
        match = RE_MESSAGE.match(line)
        if match:
            blocks[-1][2].append([[], int(match.group(2))])
            continue
        match = RE_ITEM.match(line)
        if match and blocks and blocks[-1][2]:
            blocks[-1][2][-1][0].append(match.group(1))
    flush()
    proc.wait()
    return shapes


def main():
    args = sys.argv[1:]
    if len(args) < 2 or len(args) % 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    version = subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout
    version = version.splitlines()[0] if version else "tshark"
    print(f"# Genere par tools/asterix_oracle.py avec {version.strip()} : forme des data blocks")
    print("# de chaque trame ASTERIX, `CAT:LEN:items/longueur;...|...`, un data block par")
    print("# `|`, un record par `;`, les data items par `,` et la longueur du record apres")
    print("# `/`. Les trames de meme forme sont regroupees (`1-4,9` : plages et numeros).")
    print("# capture\ttrames\tdata blocks")
    for capture, ports in zip(args[::2], args[1::2]):
        name = os.path.basename(capture)
        shapes = dissect(capture, ports)
        by_shape = {}
        malformed = {}
        for frame in sorted(shapes):
            shape, bad = shapes[frame]
            (malformed if bad else by_shape).setdefault(shape, []).append(frame)
        for shape, frames in sorted(by_shape.items(), key=lambda entry: entry[1][0]):
            print(f"{name}\t{ranges(frames)}\t{shape}")
        for shape, frames in sorted(malformed.items(), key=lambda entry: entry[1][0]):
            print(f"MALFORMED\t{name}\t{ranges(frames)}\t{shape}", file=sys.stderr)
        total = sum(len(frames) for frames in by_shape.values())
        bad = sum(len(frames) for frames in malformed.values())
        print(
            f"{name}: {total} trames conformes en {len(by_shape)} formes, {bad} malformees",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
