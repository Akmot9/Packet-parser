#!/usr/bin/env python3
"""Tableaux de la comparaison L2-L4 (#375), en Markdown, depuis les mesures
de criterion.

    cargo bench --manifest-path tools/compare/Cargo.toml
    python3 tools/compare/report.py > resultats.md

Lit `target/criterion/<groupe>/<fonction>/new/` et lance le binaire
`agreement` pour compter les trames gardees et ecartees de chaque corpus.
"""

import json
import pathlib
import platform
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CRITERION = HERE / "target" / "criterion"

# Ordre des lignes : le decoupage, puis le decodage.
FUNCTIONS = [
    ("slice_etherparse", "etherparse", "`SlicedPacket::from_ethernet`", "slicing"),
    ("slice_pnet", "pnet_packet", "views, fields not read", "slicing"),
    ("full_etherparse", "etherparse", "`PacketHeaders::from_ethernet_slice`", "full decode, L2-L4"),
    (
        "full_etherparse_slices",
        "etherparse",
        "`SlicedPacket`, then `to_header` on each view",
        "full decode, L2-L4",
    ),
    ("full_pnet", "pnet_packet", "views, every accessor", "full decode, L2-L4"),
    ("full_packet_parser", "**packet_parser**", "`parse`", "full decode, L2-L7"),
]

FRAMES = [
    ("tcp_ack", "TCP over IPv4, no payload"),
    ("tcp_data", "TCP over IPv4, 1,000 bytes or more"),
    ("udp_dns", "UDP over IPv4, DNS"),
    ("tcp_ipv6", "TCP over IPv6"),
    ("icmp", "ICMP"),
    ("vlan_udp", "UDP under an 802.1Q tag"),
]


def measure(group, function):
    """Mediane et ecart absolu median d'une iteration (ns), et le nombre de
    trames qu'une iteration decode."""
    new = CRITERION / group / function / "new"
    estimates = json.loads((new / "estimates.json").read_text())
    benchmark = json.loads((new / "benchmark.json").read_text())
    frames = benchmark["throughput"]["Elements"]
    return (
        estimates["median"]["point_estimate"] / frames,
        estimates["median_abs_dev"]["point_estimate"] / frames,
        frames,
    )


def fr(value, digits=1):
    return f"{value:.{digits}f}"


def thousands(value):
    return f"{value:,}"


def agreement():
    out = subprocess.run(
        ["cargo", "run", "--quiet", "--release", "--bin", "agreement"],
        cwd=HERE,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    rows = {}
    for line in out[1:]:
        name, *numbers = line.split("\t")
        rows[name] = dict(
            zip(
                ["read", "kept", "bytes", "not_ethernet", "out_of_scope", "disagreed"],
                map(int, numbers),
            )
        )
    return rows


def table(group, bytes_per_frame=None):
    reference = measure(group, "full_packet_parser")[0]
    head = "| Crate | Call | Level | ns per frame | ± | M frames/s |"
    rule = "|---|---|---|---:|---:|---:|"
    if bytes_per_frame:
        head += " Gbit/s |"
        rule += "---:|"
    head += " packet_parser = 1 |"
    rule += "---:|"
    lines = [head, rule]
    for function, crate, call, level in FUNCTIONS:
        ns, spread, _ = measure(group, function)
        line = f"| {crate} | {call} | {level} | {fr(ns)} | {fr(spread, 2)} | {fr(1e3 / ns)} |"
        if bytes_per_frame:
            line += f" {fr(bytes_per_frame * 8 / ns)} |"
        line += f" {fr(ns / reference, 2)} |"
        lines.append(line)
    return "\n".join(lines)


def environment():
    lock = (HERE / "Cargo.lock").read_text()
    versions = {
        name: re.search(rf'name = "{name}"\nversion = "([^"]+)"', lock).group(1)
        for name in ["etherparse", "pnet_packet", "criterion", "packet_parser"]
    }
    cpu = "?"
    for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    rustc = subprocess.run(["rustc", "-V"], capture_output=True, text=True).stdout.strip()
    governor = pathlib.Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    return versions, cpu, rustc, governor.read_text().strip() if governor.exists() else "?"


def main():
    if not CRITERION.exists():
        sys.exit("aucune mesure : lancer d'abord `cargo bench` dans tools/compare")
    corpora = agreement()
    versions, cpu, rustc, governor = environment()

    print("### Machine and versions\n")
    print(f"- CPU: {cpu}, one core, governor `{governor}`")
    print(f"- OS: {platform.system()} {platform.release()}")
    print(f"- Compiler: {rustc}, profile `opt-level = 3`, `lto = \"fat\"`, `codegen-units = 1`")
    print(
        f"- Crates: packet_parser {versions['packet_parser']} (this repository), "
        f"etherparse {versions['etherparse']}, pnet_packet {versions['pnet_packet']}, "
        f"criterion {versions['criterion']}"
    )

    print("\n### Frames measured\n")
    print("| Corpus | Frames read | Kept | Bytes | Not Ethernet | No layer 4 | Disagreement |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for name, row in corpora.items():
        print(
            f"| `{name}` | {thousands(row['read'])} | {thousands(row['kept'])} | "
            f"{thousands(row['bytes'])} | {thousands(row['not_ethernet'])} | "
            f"{thousands(row['out_of_scope'])} | {thousands(row['disagreed'])} |"
        )

    for name, row in corpora.items():
        print(f"\n### Corpus `{name}`: {thousands(row['kept'])} frames\n")
        print(table(name, row["bytes"] / row["kept"]))
        frames = measure(f"{name}_no_payload", "full_packet_parser")[2]
        print(f"\nThe {thousands(frames)} TCP frames of this corpus that carry no payload:\n")
        print(table(f"{name}_no_payload"))

    print("\n### One frame per family\n")
    print("ns per frame.\n")
    print("| Frame | " + " | ".join(f"`{f}`" for f, *_ in FUNCTIONS) + " |")
    print("|---|" + "---:|" * len(FUNCTIONS))
    for case, label in FRAMES:
        cells = [fr(measure(f"frame_{case}", function)[0]) for function, *_ in FUNCTIONS]
        print(f"| {label} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
