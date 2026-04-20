"""
MemorySuite — benchmark mémoire et scalabilité.

Mesure l'empreinte mémoire du vault CAGOULE avec 10/100/1000 entrées.
Analyse également l'effet cache (chaud vs froid).
"""

import os
import time
from bench.metrics import TimeCollector, MemoryCollector, CpuCollector
from bench.suites.base import BaseSuite, BenchmarkResult

# Tailles de vault à tester
VAULT_SIZES = [10, 100, 1000]

# Taille des valeurs stockées (1KB par entrée)
VALUE_SIZE = 1024


def create_vault(num_entries: int) -> dict:
    """
    Crée un vault avec num_entries entrées.
    Chaque entrée est une clé string et une valeur bytes de VALUE_SIZE.
    """
    vault = {}
    for i in range(num_entries):
        key = f"entry_{i:04d}"
        value = os.urandom(VALUE_SIZE)
        vault[key] = value
    return vault


def access_vault_sequentially(vault: dict) -> None:
    """Accès séquentiel à toutes les entrées du vault."""
    for key in vault:
        _ = vault[key]


def access_vault_randomly(vault: dict) -> None:
    """Accès aléatoire à toutes les entrées du vault."""
    import random
    keys = list(vault.keys())
    random.shuffle(keys)
    for key in keys:
        _ = vault[key]


class MemorySuite(BaseSuite):
    NAME = "memory"
    DESCRIPTION = "Vault memory scaling + cache hot/cold analysis"

    def __init__(
        self,
        iterations: int = 100,   # Itérations pour timing
        warmup: int = 5,
        vault_sizes: list[int] | None = None,
        entry_counts: list[int] | None = None,  # FIXED: Added alias parameter
    ):
        super().__init__(iterations=iterations, warmup=warmup)
        # Support both parameter names (for test compatibility)
        if entry_counts is not None:
            vault_sizes = entry_counts
        self.vault_sizes = vault_sizes or VAULT_SIZES
        self._timer = TimeCollector()
        self._mem = MemoryCollector()
        self._cpu = CpuCollector()

    def run(self) -> list[BenchmarkResult]:
        results: list[BenchmarkResult] = []

        # ── 1. Scalabilité du vault (création + mémoire) ──────────────
        for num_entries in self.vault_sizes:
            label = f"vault-{num_entries}"

            def _create_vault():
                return create_vault(num_entries)

            # Mesure mémoire (peak, delta, fragmentation)
            _, mem = self._mem.measure(_create_vault, label=label)

            # Mesure temps de création
            timing = self._timer.measure(
                _create_vault,
                iterations=self.iterations,
                warmup=self.warmup,
                label=label,
            )

            # Mesure CPU
            _, cpu = self._cpu.measure(_create_vault, label=label)

            # Calcul des métriques dérivées
            mb_per_entry = mem.peak_mb / num_entries if num_entries > 0 else 0
            entries_per_sec = num_entries / (timing.mean_ms / 1000) if timing.mean_ms > 0 else 0

            results.append(self._make_result(
                name=f"vault-creation-{num_entries}",
                algorithm="Vault",
                data_size_bytes=num_entries * VALUE_SIZE,
                mean_ms=timing.mean_ms,
                stddev_ms=timing.stddev_ms,
                min_ms=timing.min_ms,
                max_ms=timing.max_ms,
                p95_ms=timing.p95_ms,
                p99_ms=timing.p99_ms,
                cv_percent=timing.cv_percent,
                throughput_mbps=0.0,  # Non applicable
                peak_mb=mem.peak_mb,
                delta_mb=mem.delta_mb,
                cpu_mean_pct=cpu.cpu_mean_pct,
                cpu_peak_pct=cpu.cpu_peak_pct,
                extra={
                    "entry_count": num_entries,
                    "mb_per_entry": round(mb_per_entry, 4),
                    "entries_per_sec": round(entries_per_sec, 0),
                    "fragmentation_pct": round(mem.fragmentation_pct, 2),
                    "type": "vault_creation",
                },
            ))

        # ── 2. Cache chaud vs froid (accès séquentiel) ─────────────────
        # Crée un vault de taille fixe pour les tests de cache
        CACHE_TEST_SIZE = 100
        vault = create_vault(CACHE_TEST_SIZE)
        
        # Froid: premier accès (cache miss)
        def _cold_access():
            access_vault_sequentially(vault)
        
        cold_timing = self._timer.measure(
            _cold_access,
            iterations=1,  # Une seule mesure pour le cold start
            warmup=0,
            label="cold-cache-sequential",
        )
        
        # Chaud: second accès (cache hit)
        # D'abord, échauffer le cache
        access_vault_sequentially(vault)
        
        def _hot_access():
            access_vault_sequentially(vault)
        
        hot_timing = self._timer.measure(
            _hot_access,
            iterations=self.iterations,
            warmup=self.warmup,
            label="hot-cache-sequential",
        )
        
        cache_speedup = cold_timing.mean_ms / hot_timing.mean_ms if hot_timing.mean_ms > 0 else 1.0
        
        results.append(self._make_result(
            name="cache-sequential",
            algorithm="Cache Analysis",
            data_size_bytes=CACHE_TEST_SIZE * VALUE_SIZE,
            mean_ms=hot_timing.mean_ms,
            stddev_ms=hot_timing.stddev_ms,
            min_ms=hot_timing.min_ms,
            max_ms=hot_timing.max_ms,
            p95_ms=hot_timing.p95_ms,
            p99_ms=hot_timing.p99_ms,
            cv_percent=hot_timing.cv_percent,
            throughput_mbps=0.0,
            peak_mb=0.0,
            delta_mb=0.0,
            cpu_mean_pct=0.0,
            cpu_peak_pct=0.0,
            extra={
                "cache_type": "hot",
                "access_pattern": "sequential",
                "cold_ms": round(cold_timing.mean_ms, 3),
                "hot_ms": round(hot_timing.mean_ms, 3),
                "cache_speedup": round(cache_speedup, 1),
                "entry_count": CACHE_TEST_SIZE,
            },
        ))
        
        # ── 3. Accès aléatoire vs séquentiel ──────────────────────────
        def _random_access():
            access_vault_randomly(vault)
        
        random_timing = self._timer.measure(
            _random_access,
            iterations=self.iterations,
            warmup=self.warmup,
            label="random-access",
        )
        
        sequential_vs_random = random_timing.mean_ms / hot_timing.mean_ms if hot_timing.mean_ms > 0 else 1.0
        
        results.append(self._make_result(
            name="random-vs-sequential",
            algorithm="Access Pattern",
            data_size_bytes=CACHE_TEST_SIZE * VALUE_SIZE,
            mean_ms=random_timing.mean_ms,
            stddev_ms=random_timing.stddev_ms,
            min_ms=random_timing.min_ms,
            max_ms=random_timing.max_ms,
            p95_ms=random_timing.p95_ms,
            p99_ms=random_timing.p99_ms,
            cv_percent=random_timing.cv_percent,
            throughput_mbps=0.0,
            peak_mb=0.0,
            delta_mb=0.0,
            cpu_mean_pct=0.0,
            cpu_peak_pct=0.0,
            extra={
                "access_pattern": "random",
                "sequential_ms": round(hot_timing.mean_ms, 3),
                "random_ms": round(random_timing.mean_ms, 3),
                "random_overhead": round(sequential_vs_random, 2),
                "entry_count": CACHE_TEST_SIZE,
            },
        ))

        return results

    def measure_fragmentation(self, num_entries: int = 100) -> dict:
        """
        Mesure détaillée de la fragmentation mémoire.
        Utile pour l'analyse académique.
        """
        vault = create_vault(num_entries)
        
        # Force garbage collection
        import gc
        gc.collect()
        
        # Mesure fragmentation
        _, mem = self._mem.measure(lambda: vault, label="fragmentation-test")
        
        return {
            "entry_count": num_entries,
            "peak_mb": mem.peak_mb,
            "delta_mb": mem.delta_mb,
            "fragmentation_pct": mem.fragmentation_pct,
            "alloc_count": mem.alloc_count,
        }