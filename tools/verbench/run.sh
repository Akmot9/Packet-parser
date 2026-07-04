#!/usr/bin/env bash
# Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
# Licensed under the MIT License.
#
# Bench des timings par couche (l2/l3/l4/l7) pour chaque version publiée
# de packet_parser + la copie de travail locale.
#
# Usage : tools/verbench/run.sh [fichier_sortie.json]
#
# - Récupère sur crates.io la liste des versions non-yankées exposant la
#   feature `parse_timing` (les 0.x ne l'ont pas et sont donc ignorées).
# - Pour chaque version, régénère Cargo.toml, compile src/main.rs en release
#   et exécute le bench (le target/ est partagé, seuls packet_parser et le
#   binaire sont recompilés à chaque itération).
# - Ajoute la copie de travail locale (version lue dans ../../Cargo.toml).
# - Agrège le tout dans un JSON { "<version>": { l2_ns, l3_ns, l4_ns,
#   l7_ns, total_ns }, ... }.
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT=$(cd ../.. && pwd)
OUT_JSON=${1:-"$REPO_ROOT/perf_by_version.json"}
RESULTS=results.jsonl
: > "$RESULTS"

# Liste des versions bench-ables, triée par semver croissant.
VERSIONS=$(curl -sf "https://crates.io/api/v1/crates/packet_parser/versions" \
    -H "User-Agent: packet_parser-verbench (https://github.com/Akmot9/Packet-parser)" \
    | python3 -c '
import json, sys
versions = json.load(sys.stdin)["versions"]
nums = [
    v["num"] for v in versions
    if not v["yanked"] and "parse_timing" in (v.get("features") or {})
]
nums.sort(key=lambda n: [int(x) for x in n.split(".")])
print("\n".join(nums))
')

write_manifest() {
    # $1 : ligne de dépendance packet_parser
    cat > Cargo.toml <<EOF
[package]
name = "verbench"
version = "0.1.0"
edition = "2021"

[dependencies]
$1
hex = "0.4"

[profile.release]
opt-level = 3
EOF
}

bench_one() {
    # $1 : étiquette de version, $2 : ligne de dépendance
    write_manifest "$2"
    echo "=== $1 ===" >&2
    if cargo build --release --quiet 2> "build_$1.log"; then
        local timing
        timing=$(./target/release/verbench)
        echo "{\"version\": \"$1\", \"timing\": $timing}" >> "$RESULTS"
        rm -f "build_$1.log"
    else
        echo "échec de compilation pour $1 (voir tools/verbench/build_$1.log), version ignorée" >&2
    fi
}

for v in $VERSIONS; do
    bench_one "$v" "packet_parser = { version = \"=$v\", features = [\"parse_timing\"] }"
done

# La copie locale est suffixée "-local" pour ne pas écraser l'entrée
# crates.io quand la même version y est déjà publiée.
LOCAL_VERSION=$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | cut -d'"' -f2)
bench_one "$LOCAL_VERSION-local" "packet_parser = { path = \"$REPO_ROOT\", features = [\"parse_timing\"] }"

python3 -c '
import json, sys
out = {}
with open(sys.argv[1]) as f:
    for line in f:
        r = json.loads(line)
        out[r["version"]] = r["timing"]
with open(sys.argv[2], "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")
' "$RESULTS" "$OUT_JSON"

echo "OK : $(grep -c . "$RESULTS") versions mesurées -> $OUT_JSON" >&2
