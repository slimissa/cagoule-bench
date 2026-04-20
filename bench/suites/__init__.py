"""
Benchmark Suites Package

Available suites:
- encryption: AES-256-GCM, ChaCha20-Poly1305, CAGOULE
- kdf: Argon2id (27 combos) vs PBKDF2-SHA256
- memory: Vault scaling, cache analysis
- parallel: ProcessPoolExecutor scaling (1-8 workers)
"""

from .base import BaseSuite, BenchmarkResult
from .encryption_suite import EncryptionSuite
from .kdf_suite import KdfSuite
from .memory_suite import MemorySuite
from .parallel_suite import ParallelSuite

# Registry for dynamic discovery
ALL_SUITES = {
    "encryption": EncryptionSuite,
    "kdf": KdfSuite,
    "memory": MemorySuite,
    "parallel": ParallelSuite,
}


def get_suite(name: str) -> BaseSuite:
    """Return a suite instance by name."""
    if name not in ALL_SUITES:
        raise ValueError(f"Unknown suite: {name}. Available: {list(ALL_SUITES.keys())}")
    return ALL_SUITES[name]()


def get_all_suites() -> list[BaseSuite]:
    """Return instances of all registered suites."""
    return [cls() for cls in ALL_SUITES.values()]


def list_suites() -> list[str]:
    """Return list of available suite names."""
    return list(ALL_SUITES.keys())


__all__ = [
    "BaseSuite",
    "BenchmarkResult",
    "EncryptionSuite",
    "KdfSuite",
    "MemorySuite",
    "ParallelSuite",
    "ALL_SUITES",
    "get_suite",
    "get_all_suites",
    "list_suites",
]