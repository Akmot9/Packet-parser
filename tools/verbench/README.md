# verbench — perfs par version de la crate

Mesure les timings de parsing par couche OSI (`l2_ns`, `l3_ns`, `l4_ns`,
`l7_ns`, `total_ns`) pour **chaque version publiée** de `packet_parser` sur
crates.io, plus la copie de travail locale, et produit un JSON comparatif.

## Usage

```bash
tools/verbench/run.sh                 # écrit perf_by_version.json à la racine du repo
tools/verbench/run.sh /chemin/out.json
python3 tools/verbench/report.py      # génère perf_by_version.html depuis le JSON existant
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
  compile en release et agrège les résultats.
- `report.py` transforme le JSON agrégé en rapport HTML statique avec
  graphiques SVG, résumé des deltas et tableau détaillé.

## Prérequis

`curl`, `python3`, accès réseau vers crates.io.

Les chiffres sont des moyennes sur une seule machine, sans isolation
(pas de pinning CPU) : comparez les ordres de grandeur entre versions,
pas les nanosecondes exactes.
