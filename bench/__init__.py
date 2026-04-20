"""
cagoule-bench — Suite de benchmarking académique pour CAGOULE.

Exports principaux pour l'utilisation du package.
"""

from bench.metrics import TimeCollector, MemoryCollector, CpuCollector
from bench.suites import (
    BaseSuite,
    BenchmarkResult,
    EncryptionSuite,
    KdfSuite,
    MemorySuite,
    ParallelSuite,
    ALL_SUITES,
)
from bench.reporters import (
    ConsoleReporter,
    JsonReporter,
    CsvReporter,
    MarkdownReporter,
    HtmlReporter,
)

__all__ = [
    # Metrics
    "TimeCollector",
    "MemoryCollector",
    "CpuCollector",
    # Suites
    "BaseSuite",
    "BenchmarkResult",
    "EncryptionSuite",
    "KdfSuite",
    "MemorySuite",
    "ParallelSuite",
    "ALL_SUITES",
    # Reporters
    "ConsoleReporter",
    "JsonReporter",
    "CsvReporter",
    "MarkdownReporter",
    "HtmlReporter",
]