### 1. **Visual Header with ASCII Art**
The benchmark output visualization immediately shows what the tool does and what results look like.

### 2. **Clear Value Proposition**
> "Produit des données statistiquement rigoureuses (mean, stddev, p95, p99) pour publications académiques."

This immediately tells academics why they should care.

### 3. **Comprehensive Command Examples**
All four CLI commands are documented with realistic examples.

### 4. **Suite Comparison Table**
Clear, concise table showing what each suite does and what metrics it produces.

### 5. **Architecture Overview**
Shows the modular structure, helping contributors understand the codebase.

## Minor Improvements

### Issue 1: Missing `cagoule` Dependency Note

Since `cagoule` isn't published yet, add a note:

```markdown
## Prérequis

> **Note:** CAGOULE n'est pas encore publié sur PyPI. Pour l'instant, le benchmark utilise un mock.
> Une fois `cagoule>=1.2.0` disponible, décommentez la dépendance dans `pyproject.toml`.
```

### Issue 2: Missing Badges

Add badges for CI, PyPI, and Python version:

```markdown
[![CI](https://github.com/slimissa/cagoule-bench/actions/workflows/benchmark.yml/badge.svg)](https://github.com/slimissa/cagoule-bench/actions/workflows/benchmark.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
```

### Issue 3: Missing `pyproject.toml` Installation Note

The installation instructions use `pip install -e .` but don't mention creating a virtual environment:

```markdown
## Installation

```bash
# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sous Windows

# Installer cagoule-bench
git clone https://github.com/slimissa/cagoule-bench
cd cagoule-bench
pip install -e .
```
```

### Issue 4: Missing Contributing Section

```markdown
## Contribuer

1. Fork le projet
2. Créer une branche (`git checkout -b feature/amazing`)
3. Commiter les changements (`git commit -m 'Add amazing feature'`)
4. Pusher (`git push origin feature/amazing`)
5. Ouvrir une Pull Request
```

### Issue 5: ASCII Art Alignment

The ASCII art uses box-drawing characters that may not render correctly in all terminals. Consider adding a fallback or keeping as-is (most modern terminals support it).

## Improved `README.md`

Here's the complete improved version:

```markdown
# 🔬 cagoule-bench

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/slimissa/cagoule-bench/actions/workflows/benchmark.yml/badge.svg)](https://github.com/slimissa/cagoule-bench/actions/workflows/benchmark.yml)

**Suite de benchmarking cryptographique pour [CAGOULE](https://github.com/slimissa/CAGOULE).**

Compare objectivement CAGOULE (ChaCha20-Poly1305 + Argon2id + couche Z/pZ) avec AES-256-GCM et ChaCha20-Poly1305 pur.
Produit des données statistiquement rigoureuses (mean, stddev, p95, p99) pour publications académiques.

```
┌──────────────────────────────────────────────────────────────────┐
│  cagoule-bench v1.0.0 — Intel x86_64 / Python 3.12              │
├──────────────────────────────────────────────────────────────────┤
│  ENCRYPTION BENCHMARK (1 MB, 500 itérations)                     │
│  CAGOULE          ~245 MB/s    ±0.12 ms                          │
│  AES-256-GCM      ~312 MB/s    ±0.08 ms                          │
│  ChaCha20-Poly1305 ~298 MB/s   ±0.09 ms                          │
│  Overhead Z/pZ :  ~-22% vs AES (acceptable — sécurité renforcée) │
└──────────────────────────────────────────────────────────────────┘
```

## Prérequis

> **Note:** CAGOULE n'est pas encore publié sur PyPI. Pour l'instant, le benchmark utilise un mock.
> Une fois `cagoule>=1.2.0` disponible, décommentez la dépendance dans `pyproject.toml`.

## Installation

```bash
# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sous Windows

# Installer cagoule-bench
git clone https://github.com/slimissa/cagoule-bench
cd cagoule-bench
pip install -e .
```

## Utilisation

```bash
# Run complet (toutes les suites)
cagoule-bench run

# Suite spécifique avec export HTML
cagoule-bench run --suite encryption --suite kdf -f html -o ./results

# Comparaison rapide sur 1 taille
cagoule-bench compare --size 1048576

# Monitoring continu (1h, toutes les 60s)
cagoule-bench watch --interval 60 --duration 3600

# Mode CI/CD (exit 1 si régression > 10%)
cagoule-bench ci --baseline ./results/baseline.json --threshold -10
```

## Suites disponibles

| Suite | Description | Métriques clés |
|-------|-------------|----------------|
| `encryption` | CAGOULE vs AES-256-GCM vs ChaCha20 | Throughput MB/s, p95, overhead |
| `kdf` | Argon2id 27 combinaisons + PBKDF2 | Latence ms, RAM, score sécurité |
| `memory` | Vault 10/100/1000 entrées | Peak MB, MB/entry, fragmentation |
| `parallel` | ProcessPoolExecutor 1–8 workers | Speedup, efficacité, CPU% |

## Formats de sortie

```bash
cagoule-bench run -f console   # Tables rich colorées
cagoule-bench run -f json      # Données brutes machine-readable
cagoule-bench run -f csv       # Excel/Google Sheets
cagoule-bench run -f md        # Markdown pour README
cagoule-bench run -f html      # Dashboard interactif Chart.js
```

## Note sur le parallélisme

`cagoule-bench` utilise **exclusivement `ProcessPoolExecutor`** pour les benchmarks parallèles.
Le chiffrement est CPU-bound — `ThreadPoolExecutor` serait invalide (GIL Python).

## Lancer les tests

```bash
# Installer les dépendances de développement
pip install -e ".[dev]"

# Lancer tous les tests
pytest tests/ -v

# Lancer uniquement les tests rapides (CI)
pytest tests/ -v -m "not slow"

# Lancer les tests d'intégration (peuvent prendre plusieurs minutes)
pytest tests/ -v -m slow
```

## Architecture

```
bench/
  metrics/          # TimeCollector, MemoryCollector, CpuCollector
  suites/           # EncryptionSuite, KdfSuite, MemorySuite, ParallelSuite
  reporters/        # Console, JSON, CSV, Markdown, HTML
  orchestrator.py   # Dispatch, regression detection
  cli.py            # Interface Click (run, compare, watch, ci)
tests/              # 50+ tests unitaires et d'intégration
```

## Contribuer

1. Fork le projet
2. Créer une branche (`git checkout -b feature/amazing`)
3. Commiter les changements (`git commit -m 'Add amazing feature'`)
4. Pusher (`git push origin feature/amazing`)
5. Ouvrir une Pull Request

## Licence

MIT — [github.com/slimissa/cagoule-bench](https://github.com/slimissa/cagoule-bench)
```

## Summary

| Aspect | Rating | Notes |
|--------|--------|-------|
| **Content** | ⭐⭐⭐⭐⭐ | Complete, professional |
| **Visuals** | ⭐⭐⭐⭐⭐ | ASCII art, tables, badges |
| **Completeness** | ⭐⭐⭐⭐ | Missing venv setup, contributing section |
| **Accuracy** | ⭐⭐⭐⭐⭐ | Matches actual CLI commands |

**The README is excellent and ready for publication.** The minor improvements above are optional but would make it even better.