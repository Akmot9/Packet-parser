# tools/lab : l'etabli

Outils de mesure et de capture autour de `packet_parser`. Ils ne font pas
partie de la crate publiee ni de son workspace : ce dossier a son propre
workspace Cargo et son propre `Cargo.lock` (#223).

| Dossier | Role |
|---|---|
| `benchmark_db/` | parse des PCAP locaux et ecrit des evenements JSONL (durees, timings OSI avec `parse_timing`) dans `~/.local/share/packet_parser_bench/jsonl/` |
| `ingestor/` | charge ces JSONL dans Postgres |
| `dashboards/` | tableaux de bord Grafana |
| `docker-compose.yml` | Postgres, Grafana et l'ingestor |
| `integration_test/` | capture live (`pnet`) passee a `packet_parser` |
| `see_unparsable/` | capture live, n'affiche que ce que la crate ne sait pas lire |
| `oui.csv` | extrait de la table OUI IEEE, lu par aucun code (la crate embarque la sienne) |

## Usage

```bash
sudo apt-get install libpcap-dev        # pcap et pnet lient la libpcap systeme
cd tools/lab
cargo run -p benchmark_db --release
docker compose up -d                    # Postgres, Grafana, ingestor
```

La CI verifie seulement que ces outils compilent encore (job `lab`). Leurs
dependances ne passent pas par `cargo audit`.

Les mesures par version publiee sont dans [`../verbench`](../verbench).
