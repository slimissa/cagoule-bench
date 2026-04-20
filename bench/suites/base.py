"""
BaseSuite — interface abstraite pour toutes les suites de benchmarks.

Chaque suite retourne une liste de BenchmarkResult, structure
commune consommée par tous les reporters.
"""

from __future__ import annotations
import platform
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BenchmarkResult:
    """Résultat structuré d'un benchmark individuel."""

    suite: str
    name: str
    algorithm: str
    data_size_bytes: int = 0
    iterations: int = 0
    warmup: int = 0

    # Métriques temps
    mean_ms: float = 0.0
    stddev_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    cv_percent: float = 0.0

    # Débit
    throughput_mbps: float = 0.0

    # Mémoire
    peak_mb: float = 0.0
    delta_mb: float = 0.0

    # CPU (optionnel)
    cpu_mean_pct: float = 0.0
    cpu_peak_pct: float = 0.0

    # Metadata
    platform: str = field(default_factory=lambda: platform.machine())
    python_version: str = field(default_factory=lambda: platform.python_version())
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    extra: dict = field(default_factory=dict)

    def overhead_vs(self, other: "BenchmarkResult") -> float:
        """Overhead en % par rapport à un autre résultat (négatif = plus lent)."""
        if other.throughput_mbps == 0:
            return 0.0
        return (self.throughput_mbps - other.throughput_mbps) / other.throughput_mbps * 100

    def to_dict(self) -> dict:
        return {
            "suite": self.suite,
            "name": self.name,
            "algorithm": self.algorithm,
            "data_size_bytes": self.data_size_bytes,
            "iterations": self.iterations,
            "warmup": self.warmup,
            "timing": {
                "mean_ms": round(self.mean_ms, 4),
                "stddev_ms": round(self.stddev_ms, 4),
                "min_ms": round(self.min_ms, 4),
                "max_ms": round(self.max_ms, 4),
                "p95_ms": round(self.p95_ms, 4),
                "p99_ms": round(self.p99_ms, 4),
                "cv_percent": round(self.cv_percent, 2),
            },
            "throughput_mbps": round(self.throughput_mbps, 3),
            "memory": {
                "peak_mb": round(self.peak_mb, 4),
                "delta_mb": round(self.delta_mb, 4),
            },
            "cpu": {
                "mean_pct": round(self.cpu_mean_pct, 2),
                "peak_pct": round(self.cpu_peak_pct, 2),
            },
            "meta": {
                "platform": self.platform,
                "python_version": self.python_version,
                "timestamp": self.timestamp,
            },
            "extra": self.extra,
        }


class BaseSuite(ABC):
    """Interface abstraite pour les suites de benchmarks."""

    NAME: str = "base"
    DESCRIPTION: str = ""

    def __init__(self, iterations: int = 1000, warmup: int = 10):
        self.iterations = iterations
        self.warmup = warmup

    @abstractmethod
    def run(self) -> list[BenchmarkResult]:
        """Exécute la suite et retourne les résultats."""

    def _make_result(self, name: str, algorithm: str, **kwargs) -> BenchmarkResult:
        return BenchmarkResult(
            suite=self.NAME,
            name=name,
            algorithm=algorithm,
            iterations=self.iterations,
            warmup=self.warmup,
            **kwargs,
        )
