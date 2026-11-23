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
#   et garde le binaire (le target/ est partagé, seuls packet_parser et le
#   binaire sont recompilés à chaque itération).
# - Ajoute la copie de travail locale (version lue dans ../../Cargo.toml).
# - Mesure ensuite tous les binaires, VERBENCH_ROUNDS fois (15 par défaut),
#   sur un seul cœur (VERBENCH_CORE, le dernier par défaut) et dans un ordre
#   qui tourne d'une passe à l'autre : un seul tir par version, pris juste
#   après sa compilation, bougeait de 20 à 80 % d'un relevé à l'autre.
# - Garde la médiane de chaque couche et l'écrit dans un JSON
#   { "<version>": { l2_ns, l3_ns, l4_ns, l7_ns, total_ns }, ... }.
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT=$(cd ../.. && pwd)
OUT_JSON=${1:-"$REPO_ROOT/tools/verbench/perf_by_version.json"}
RESULTS=results.jsonl
ROUNDS=${VERBENCH_ROUNDS:-15}
BINS=target/verbench-bins
: > "$RESULTS"
rm -rf "$BINS"
mkdir -p "$BINS"

# Un cœur pour toute la mesure, quand taskset existe (Linux) : le processus
# ne migre pas, et le cœur reste à sa fréquence entre deux binaires.
PIN=()
if command -v taskset > /dev/null 2>&1; then
    PIN=(taskset -c "${VERBENCH_CORE:-$(($(nproc) - 1))}")
fi

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

# Le harnais est son propre workspace : il se compile ou que soit le depot,
# y compris dans un worktree pose sous un autre checkout.
[workspace]
EOF
}

LABELS=()

build_one() {
    # $1 : étiquette de version, $2 : ligne de dépendance
    write_manifest "$2"
    echo "=== compilation $1 ===" >&2
    if cargo build --release --quiet 2> "build_$1.log"; then
        cp target/release/verbench "$BINS/$1"
        LABELS+=("$1")
        rm -f "build_$1.log"
    else
        echo "échec de compilation pour $1 (voir tools/verbench/build_$1.log), version ignorée" >&2
    fi
}

for v in $VERSIONS; do
    build_one "$v" "packet_parser = { version = \"=$v\", features = [\"parse_timing\"] }"
done

# La copie locale est suffixée "-local" pour ne pas écraser l'entrée
# crates.io quand la même version y est déjà publiée.
LOCAL_VERSION=$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | cut -d'"' -f2)
build_one "$LOCAL_VERSION-local" "packet_parser = { path = \"$REPO_ROOT\", features = [\"parse_timing\"] }"

# Chaque passe part d'une version différente : aucune ne tire toujours la
# première, ni toujours derrière la même voisine.
COUNT=${#LABELS[@]}
for ((round = 0; round < ROUNDS; round++)); do
    echo "=== passe $((round + 1))/$ROUNDS ===" >&2
    for ((i = 0; i < COUNT; i++)); do
        label=${LABELS[$(((i + round * 7) % COUNT))]}
        timing=$(${PIN[@]+"${PIN[@]}"} "$BINS/$label")
        echo "{\"version\": \"$label\", \"round\": $round, \"timing\": $timing}" >> "$RESULTS"
    done
done

# Médiane de chaque couche sur les passes ; l'étendue du total, rapportée à
# sa médiane, dit le bruit du relevé.
python3 -c '
import json, statistics, sys
rounds = {}
with open(sys.argv[1]) as f:
    for line in f:
        r = json.loads(line)
        rounds.setdefault(r["version"], []).append(r["timing"])
out = {}
spreads = []
for version, timings in rounds.items():
    out[version] = {
        key: int(statistics.median(t[key] for t in timings)) for key in timings[0]
    }
    totals = [t["total_ns"] for t in timings]
    spreads.append((max(totals) - min(totals)) / statistics.median(totals))
with open(sys.argv[2], "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")
print(
    "étendue du total sur les passes : médiane %.1f %%, pire version %.1f %%"
    % (100 * statistics.median(spreads), 100 * max(spreads)),
    file=sys.stderr,
)
' "$RESULTS" "$OUT_JSON"

python3 report.py "$OUT_JSON" --svg "$REPO_ROOT/images/perf_by_version.svg"

echo "OK : $COUNT versions mesurées, $ROUNDS passes -> $OUT_JSON" >&2
