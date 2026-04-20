"""
KdfSuite — benchmark des paramètres KDF.

Explore 27 combinaisons Argon2id (t × m × p)
et compare avec PBKDF2-SHA256 sur 3 niveaux d'itérations.
"""

import os
import math
import hashlib
import itertools
from argon2.low_level import hash_secret_raw, Type
from bench.metrics import TimeCollector, MemoryCollector, CpuCollector
from bench.suites.base import BaseSuite, BenchmarkResult

PASSWORD = b"cagoule-bench-kdf-test-password"
SALT = os.urandom(16)

# Grille de paramètres Argon2id
TIME_COSTS   = [1, 3, 5]
MEMORY_COSTS = [16_384, 65_536, 131_072]   # en KiB : 16MB, 64MB, 128MB
PARALLELISM  = [1, 2, 4]

# PBKDF2 niveaux de comparaison
PBKDF2_ITERATIONS = [100_000, 300_000, 600_000]


class KdfSuite(BaseSuite):
    NAME = "kdf"
    DESCRIPTION = "Argon2id parameter grid + PBKDF2-SHA256 comparison"

    def __init__(
        self,
        iterations: int = 5,   # KDF est lent — 5 mesures suffisent
        warmup: int = 1,
        time_costs: list[int] | None = None,
        memory_costs: list[int] | None = None,
        parallelism: list[int] | None = None,
    ):
        super().__init__(iterations=iterations, warmup=warmup)
        self.time_costs   = time_costs   or TIME_COSTS
        self.memory_costs = memory_costs or MEMORY_COSTS
        self.parallelism  = parallelism  or PARALLELISM
        self._timer = TimeCollector()
        self._mem   = MemoryCollector()
        self._cpu   = CpuCollector()

    def run(self) -> list[BenchmarkResult]:
        results: list[BenchmarkResult] = []

        # ── Argon2id grid ─────────────────────────────────────────────
        combos = list(itertools.product(self.time_costs, self.memory_costs, self.parallelism))
        
        for t, m, p in combos:
            m_mb = m // 1024
            label = f"t={t},m={m_mb}MB,p={p}"

            def _argon2(t=t, m=m, p=p):
                return hash_secret_raw(
                    secret=PASSWORD,
                    salt=SALT,
                    time_cost=t,
                    memory_cost=m,
                    parallelism=p,
                    hash_len=32,          # 256-bit output
                    type=Type.ID,         # Argon2id (hybrid)
                )

            # Warmup memory collector
            for _ in range(2):
                self._mem.measure(_argon2)
            
            # Measure memory
            _, mem = self._mem.measure(_argon2, label=f"argon2id-{label}")
            
            # Measure timing
            timing = self._timer.measure(
                _argon2,
                iterations=self.iterations,
                warmup=self.warmup,
                label=label,
            )
            
            # Measure CPU (important for parallelism scaling)
            _, cpu = self._cpu.measure(_argon2, label=f"argon2id-{label}")

            # Security score heuristic: log2(t * m * p)
            # Higher = more resistant to GPU/ASIC attacks
            security_score = round(math.log2(t * m * p), 1)

            results.append(self._make_result(
                name=f"argon2id-{label}",
                algorithm="Argon2id",
                data_size_bytes=0,  # KDF doesn't process variable data
                mean_ms=timing.mean_ms,
                stddev_ms=timing.stddev_ms,
                min_ms=timing.min_ms,
                max_ms=timing.max_ms,
                p95_ms=timing.p95_ms,
                p99_ms=timing.p99_ms,
                cv_percent=timing.cv_percent,  # Property, not method
                throughput_mbps=0.0,  # Not applicable for KDF
                peak_mb=mem.peak_mb,
                delta_mb=mem.delta_mb,
                cpu_mean_pct=cpu.cpu_mean_pct,
                cpu_peak_pct=cpu.cpu_peak_pct,
                extra={
                    "t_cost": t,
                    "m_cost_mb": m_mb,
                    "parallelism": p,
                    "security_score": security_score,
                    "type": "Argon2id",
                },
            ))

        # ── PBKDF2-SHA256 comparison ──────────────────────────────────
        for iters in PBKDF2_ITERATIONS:
            label = f"pbkdf2-sha256-{iters//1000}k"

            def _pbkdf2(iters=iters):
                return hashlib.pbkdf2_hmac(
                    "sha256",
                    PASSWORD,
                    SALT,
                    iters,
                    dklen=32,  # 256-bit output
                )

            # Warmup
            for _ in range(2):
                self._mem.measure(_pbkdf2)
            
            # Measure memory
            _, mem = self._mem.measure(_pbkdf2, label=label)
            
            # Measure timing
            timing = self._timer.measure(
                _pbkdf2,
                iterations=self.iterations,
                warmup=self.warmup,
                label=label,
            )
            
            # Measure CPU
            _, cpu = self._cpu.measure(_pbkdf2, label=label)

            # Security score: log2(iterations)
            security_score = round(math.log2(iters), 1)

            results.append(self._make_result(
                name=label,
                algorithm="PBKDF2-SHA256",
                data_size_bytes=0,
                mean_ms=timing.mean_ms,
                stddev_ms=timing.stddev_ms,
                min_ms=timing.min_ms,
                max_ms=timing.max_ms,
                p95_ms=timing.p95_ms,
                p99_ms=timing.p99_ms,
                cv_percent=timing.cv_percent,
                throughput_mbps=0.0,
                peak_mb=mem.peak_mb,
                delta_mb=mem.delta_mb,
                cpu_mean_pct=cpu.cpu_mean_pct,
                cpu_peak_pct=cpu.cpu_peak_pct,
                extra={
                    "iterations": iters,
                    "security_score": security_score,
                    "type": "PBKDF2-SHA256",
                },
            ))

        return results