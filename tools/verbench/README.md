# verbench — perfs par version de la crate

Mesure les timings de parsing par couche OSI (`l2_ns`, `l3_ns`, `l4_ns`,
`l7_ns`, `total_ns`) pour **chaque version publiée** de `packet_parser` sur
crates.io, plus la copie de travail locale, et produit un JSON comparatif.

## Usage

```bash
tools/verbench/run.sh                 # écrit perf_by_version.json dans tools/verbench/
tools/verbench/run.sh /chemin/out.json
python3 tools/verbench/report.py      # génère perf_by_version.html depuis le JSON existant
python3 tools/verbench/report.py --svg images/perf_by_version.svg   # et la courbe du README
```

`run.sh` génère aussi automatiquement un rapport HTML autonome à côté du JSON
(`perf_by_version.html` par défaut). Le fichier s'ouvre directement dans un
navigateur et ne dépend pas de Docker, Postgres, Grafana ou d'un CDN.

## Sortie

```json
{
  "1.5.5": { "l2_ns": 566, "l3_ns": 892, "l4_ns": 45, "l7_ns": 181, "total_ns": 1846 },
  "1.6.0": { "l2_ns": 521, "l3_ns": 57,  "l4_ns": 45, "l7_ns": 207, "total_ns": 990 }
}
```

## Fonctionnement

- La liste des versions est récupérée via l'API crates.io ; seules les
  versions non-yankées exposant la feature `parse_timing` sont retenues
  (donc 1.0.0+, les 0.x n'ont pas cette feature).
- `src/main.rs` parse 200 000 fois (après 10 000 itérations de warmup) le
  paquet IPv6/TCP de référence des tests via `PacketFlow::try_from_timed`,
  et imprime la moyenne de chaque couche.
- `run.sh` régénère le `Cargo.toml` du harnais pour chaque version (c'est
  pourquoi il est dans `.gitignore` et le dossier est exclu du workspace),
  compile en release et garde chaque binaire. Le manifeste généré porte son
  propre `[workspace]` : le harnais se compile aussi depuis un worktree posé
  sous un autre checkout.
- Une fois tout compilé, `run.sh` mesure tous les binaires 15 fois
  (`VERBENCH_ROUNDS`), sur un seul cœur quand `taskset` existe
  (`VERBENCH_CORE` ; par défaut le dernier de la liste d'affinité du
  processus, et sans épinglage si ce cœur est refusé), dans un ordre qui
  tourne d'une passe à l'autre. Le JSON garde la médiane de chaque couche, et `run.sh`
  affiche l'étendue du total sur les passes.
- `report.py` transforme le JSON agrégé en rapport HTML statique avec
  graphiques SVG, résumé des deltas et tableau détaillé.

## Prérequis

`curl`, `python3`, accès réseau vers crates.io ; `taskset` (Linux) pour
tenir la mesure sur un cœur, sans quoi elle tourne non épinglée.

## Ce que valent les chiffres

Chaque chiffre est la médiane de 15 passes, sur un cœur d'une seule
machine. Le 2026-11-23, deux relevés complets faits à la suite se
recoupent à 2,5 % près (0,8 % en médiane), alors qu'un autre banc occupait
un cœur de la machine. Jusque-là `run.sh` tirait chaque version une seule
fois, juste après sa compilation : dans les mêmes conditions, deux relevés
s'écartaient de 20 à 86 % sur une même version.

Comparez donc les tendances entre versions, pas les nanosecondes exactes,
et ne concluez rien d'un écart de moins de 3 %. Le paquet de référence est
un seul cas, le pire pour la couche 7 : sa charge est chiffrée, aucun
protocole ne s'y reconnaît et toutes les sondes aveugles de TCP s'exécutent.
