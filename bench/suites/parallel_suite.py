"""
ParallelSuite — benchmark parallélisme ProcessPoolExecutor.

Mesure le speedup du chiffrement parallèle avec 1, 2, 4, 8 workers.
CPU-bound uniquement — GIL non-impactant.
"""

import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from bench.metrics import TimeCollector, MemoryCollector, CpuCollector
from bench.suites.base import BaseSuite, BenchmarkResult

# Configuration
WORKER_COUNTS = [1, 2, 4, 8]
NUM_OPERATIONS = 1000  # Nombre total d'opérations de chiffrement
DATA_SIZE = 1024 * 1024  # 1MB par opération

# Données de test
TEST_DATA = os.urandom(DATA_SIZE)
PASSWORD = b"cagoule-bench-parallel-test"


def _encrypt_single(_: int) -> bytes:
    """
    Opération de chiffrement individuelle.
    L'argument _ est ignoré (utilisé pour map avec range).
    
    TODO: Remplacer par le vrai chiffrement CAGOULE quand disponible.
    """
    # Mock encryption (XOR simple pour les tests)
    # À remplacer par: from cagoule import encrypt; return encrypt(TEST_DATA, PASSWORD)
    key = PASSWORD * (len(TEST_DATA) // len(PASSWORD) + 1)
    return bytes(p ^ k for p, k in zip(TEST_DATA, key[:len(TEST_DATA)]))


def run_parallel(workers: int, num_ops: int) -> tuple[float, float]:
    """
    Exécute num_ops opérations en parallèle avec workers processus.
    
    Returns:
        (duration_seconds, cpu_percent_avg)
    """
    import psutil
    
    process = psutil.Process()
    cpu_before = process.cpu_percent(interval=None)
    
    start = time.perf_counter()
    
    with ProcessPoolExecutor(max_workers=workers) as executor:
        # Soumettre toutes les tâches
        futures = [executor.submit(_encrypt_single, i) for i in range(num_ops)]
        
        # Attendre la completion
        results = []
        for future in as_completed(futures):
            results.append(future.result())
    
    duration = time.perf_counter() - start
    
    cpu_after = process.cpu_percent(interval=None)
    cpu_avg = (cpu_before + cpu_after) / 2
    
    return duration, cpu_avg


def run_sequential(num_ops: int) -> float:
    """Exécution séquentielle (baseline pour speedup)."""
    start = time.perf_counter()
    for i in range(num_ops):
        _encrypt_single(i)
    return time.perf_counter() - start


class ParallelSuite(BaseSuite):
    NAME = "parallel"
    DESCRIPTION = "ProcessPoolExecutor scaling — chiffrement CPU-bound"

    def __init__(
        self,
        iterations: int = 3,  # 3 runs par configuration pour stabilité
        warmup: int = 1,
        worker_counts: list[int] | None = None,
        num_operations: int = NUM_OPERATIONS,
        total_ops: int | None = None,  # FIXED: Added alias parameter for test compatibility
    ):
        super().__init__(iterations=iterations, warmup=warmup)
        # Support both parameter names (for test compatibility)
        if total_ops is not None:
            num_operations = total_ops
        self.worker_counts = worker_counts or WORKER_COUNTS
        self.num_operations = num_operations
        self._timer = TimeCollector()
        self._mem = MemoryCollector()
        self._cpu = CpuCollector()

    def run(self) -> list[BenchmarkResult]:
        results: list[BenchmarkResult] = []
        
        # ── 1. Baseline séquentielle (workers=1) ──────────────────────
        def _sequential():
            return run_sequential(self.num_operations)
        
        # Mesure baseline
        seq_duration = self._timer.measure(
            _sequential,
            iterations=self.iterations,
            warmup=self.warmup,
            label="sequential-baseline",
        )
        
        baseline_time_ms = seq_duration.mean_ms
        
        results.append(self._make_result(
            name=f"sequential-{self.num_operations}ops",
            algorithm="Sequential",
            data_size_bytes=self.num_operations * DATA_SIZE,
            mean_ms=baseline_time_ms,
            stddev_ms=seq_duration.stddev_ms,
            min_ms=seq_duration.min_ms,
            max_ms=seq_duration.max_ms,
            p95_ms=seq_duration.p95_ms,
            p99_ms=seq_duration.p99_ms,
            cv_percent=seq_duration.cv_percent,
            throughput_mbps=(self.num_operations * DATA_SIZE / 1_048_576) / (baseline_time_ms / 1000),
            peak_mb=0.0,
            delta_mb=0.0,
            cpu_mean_pct=0.0,
            cpu_peak_pct=0.0,
            extra={
                "workers": 1,
                "num_operations": self.num_operations,
                "data_size_mb": DATA_SIZE / 1_048_576,
                "is_baseline": True,
            },
        ))
        
        # ── 2. Tests parallèles pour chaque nombre de workers ──────────
        for workers in self.worker_counts:
            if workers == 1:
                continue  # Déjà fait comme baseline
                
            label = f"workers-{workers}"
            
            def _parallel():
                duration, _ = run_parallel(workers, self.num_operations)
                return duration
            
            # Mesure mémoire
            _, mem = self._mem.measure(_parallel, label=label)
            
            # Mesure timing
            timing = self._timer.measure(
                _parallel,
                iterations=self.iterations,
                warmup=self.warmup,
                label=label,
            )
            
            # Mesure CPU
            _, cpu = self._cpu.measure(_parallel, label=label)
            
            # Calcul du speedup
            speedup_ratio = baseline_time_ms / timing.mean_ms if timing.mean_ms > 0 else 1.0
            parallel_efficiency = (speedup_ratio / workers) * 100
            
            # Throughput total (MB/s agrégé)
            total_data_mb = (self.num_operations * DATA_SIZE) / 1_048_576
            throughput_mbps = total_data_mb / (timing.mean_ms / 1000)
            
            results.append(self._make_result(
                name=f"parallel-{self.num_operations}ops-{workers}workers",
                algorithm=f"Parallel ({workers} workers)",
                data_size_bytes=self.num_operations * DATA_SIZE,
                mean_ms=timing.mean_ms,
                stddev_ms=timing.stddev_ms,
                min_ms=timing.min_ms,
                max_ms=timing.max_ms,
                p95_ms=timing.p95_ms,
                p99_ms=timing.p99_ms,
                cv_percent=timing.cv_percent,
                throughput_mbps=throughput_mbps,
                peak_mb=mem.peak_mb,
                delta_mb=mem.delta_mb,
                cpu_mean_pct=cpu.cpu_mean_pct,
                cpu_peak_pct=cpu.cpu_peak_pct,
                extra={
                    "workers": workers,
                    "num_operations": self.num_operations,
                    "data_size_mb": DATA_SIZE / 1_048_576,
                    "speedup_ratio": round(speedup_ratio, 3),
                    "parallel_efficiency_pct": round(parallel_efficiency, 1),
                    "ops_per_sec": round(self.num_operations / (timing.mean_ms / 1000), 0),
                    "is_baseline": False,
                },
            ))
        
        # ── 3. Analyse du GIL (documentation uniquement) ──────────────
        # Note: Le chiffrement étant CPU-bound, ThreadPoolExecutor serait
        # limité par le GIL Python. ProcessPoolExecutor est obligatoire.
        
        results.append(self._make_result(
            name="gil-analysis",
            algorithm="Documentation",
            data_size_bytes=0,
            mean_ms=0.0,
            stddev_ms=0.0,
            min_ms=0.0,
            max_ms=0.0,
            p95_ms=0.0,
            p99_ms=0.0,
            cv_percent=0.0,
            throughput_mbps=0.0,
            peak_mb=0.0,
            delta_mb=0.0,
            cpu_mean_pct=0.0,
            cpu_peak_pct=0.0,
            extra={
                "note": "ProcessPoolExecutor utilisé exclusivement car le chiffrement est CPU-bound. ThreadPoolExecutor serait limité par le GIL Python.",
                "reason": "CPU-bound operation + GIL = ThreadPoolExecutor invalide pour benchmarks académiques",
            },
        ))
        
        return results

    def measure_speedup_curve(self) -> dict:
        """
        Mesure la courbe de speedup complète pour analyse académique.
        Retourne les données pour publication (tableau/plot).
        """
        results = {}
        
        # Baseline
        seq_time = run_sequential(self.num_operations)
        results[1] = {"time_ms": seq_time * 1000, "speedup": 1.0, "efficiency": 100.0}
        
        # Tests parallèles
        for workers in self.worker_counts:
            if workers == 1:
                continue
            
            # Moyenne sur iterations
            times = []
            for _ in range(self.iterations):
                duration, _ = run_parallel(workers, self.num_operations)
                times.append(duration)
            
            avg_time = sum(times) / len(times)
            speedup = seq_time / avg_time
            
            results[workers] = {
                "time_ms": avg_time * 1000,
                "speedup": round(speedup, 3),
                "efficiency": round((speedup / workers) * 100, 1),
            }
        
        return results

    def get_optimal_workers(self) -> int:
        """
        Détermine le nombre optimal de workers basé sur la courbe de speedup.
        Utile pour les recommandations de déploiement.
        """
        curve = self.measure_speedup_curve()
        
        optimal = 1
        best_efficiency = 100.0
        
        for workers, metrics in curve.items():
            if metrics["efficiency"] > best_efficiency and metrics["efficiency"] > 70:
                best_efficiency = metrics["efficiency"]
                optimal = workers
        
        return optimal