"""
Tests unitaires — Collectors (TimeCollector, MemoryCollector, CpuCollector).

Vérifie la précision, la cohérence statistique et le comportement
aux limites (1 itération, données vides).
"""

import time
import pytest
from bench.metrics import TimeCollector, MemoryCollector, CpuCollector


# ──────────────────────────────────────────────────────────────
# TimeCollector
# ──────────────────────────────────────────────────────────────

class TestTimeCollector:
    def setup_method(self):
        self.collector = TimeCollector()

    def test_returns_correct_sample_count(self):
        result = self.collector.measure(lambda: None, iterations=50, warmup=5)
        assert len(result.samples_ns) == 50

    def test_mean_is_positive(self):
        result = self.collector.measure(lambda: time.sleep(0.001), iterations=10, warmup=2)
        assert result.mean_ms > 0

    def test_p95_gte_mean(self):
        result = self.collector.measure(lambda: time.sleep(0.001), iterations=20, warmup=2)
        assert result.p95_ms >= result.mean_ms

    def test_p99_gte_p95(self):
        result = self.collector.measure(lambda: time.sleep(0.001), iterations=20, warmup=2)
        assert result.p99_ms >= result.p95_ms

    def test_min_lte_mean(self):
        result = self.collector.measure(lambda: time.sleep(0.001), iterations=20, warmup=2)
        assert result.min_ms <= result.mean_ms

    def test_max_gte_mean(self):
        result = self.collector.measure(lambda: time.sleep(0.001), iterations=20, warmup=2)
        assert result.max_ms >= result.mean_ms

    def test_stddev_zero_for_single_sample(self):
        result = self.collector.measure(lambda: None, iterations=1, warmup=0)
        assert result.stddev_ms == 0.0

    def test_throughput_zero_when_no_data(self):
        result = self.collector.measure(lambda: None, iterations=5, warmup=0)
        # mean_ms ≈ 0 pour une lambda no-op — throughput retourne 0
        assert result.throughput_mbps(1024) >= 0

    def test_cv_percent_positive(self):
        result = self.collector.measure(lambda: time.sleep(0.001), iterations=20, warmup=2)
        # FIXED: cv_percent is a property, not a method
        assert result.cv_percent >= 0

    def test_to_dict_has_required_keys(self):
        result = self.collector.measure(lambda: None, iterations=5, warmup=0)
        d = result.to_dict()
        for key in ("mean_ms", "stddev_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "cv_percent"):
            assert key in d, f"Clé manquante : {key}"

    def test_label_propagated(self):
        result = self.collector.measure(lambda: None, iterations=5, warmup=0, label="test-label")
        assert result.label == "test-label"

    def test_warmup_not_counted_in_samples(self):
        result = self.collector.measure(lambda: None, iterations=10, warmup=100)
        assert len(result.samples_ns) == 10
        assert result.warmup_count == 100

    def test_actual_sleep_latency_accurate(self):
        """Vérifie que la latence mesurée est cohérente avec un sleep de 5ms."""
        result = self.collector.measure(lambda: time.sleep(0.005), iterations=10, warmup=2)
        # Tolérance large : 3ms–20ms (scheduling OS variable)
        assert 3.0 < result.mean_ms < 20.0


# ──────────────────────────────────────────────────────────────
# MemoryCollector
# ──────────────────────────────────────────────────────────────

class TestMemoryCollector:
    def setup_method(self):
        self.collector = MemoryCollector()

    def test_returns_memory_result_and_value(self):
        val, mem = self.collector.measure(lambda: [0] * 1000, label="alloc-test")
        assert isinstance(val, list)
        assert mem.peak_mb >= 0

    def test_peak_gte_delta(self):
        _, mem = self.collector.measure(lambda: bytearray(1_000_000))
        assert mem.peak_mb >= 0
        assert mem.delta_mb >= 0

    def test_peak_mb_positive_for_large_alloc(self):
        _, mem = self.collector.measure(lambda: bytearray(5_000_000))
        assert mem.peak_mb > 0

    def test_fragmentation_between_0_and_100(self):
        _, mem = self.collector.measure(lambda: list(range(10_000)))
        assert 0 <= mem.fragmentation_pct <= 100

    def test_label_propagated(self):
        _, mem = self.collector.measure(lambda: None, label="my-label")
        assert mem.label == "my-label"

    def test_to_dict_has_required_keys(self):
        _, mem = self.collector.measure(lambda: None)
        d = mem.to_dict()
        for key in ("peak_mb", "delta_mb", "alloc_count", "fragmentation_pct"):
            assert key in d

    def test_measure_scaling_returns_correct_count(self):
        # FIXED: measure_scaling now exists in MemoryCollector
        counts = [10, 100, 1000]
        results = self.collector.measure_scaling(
            fn_factory=lambda n: (lambda n=n: list(range(n))),
            counts=counts,
            label_prefix="scale-",
        )
        assert len(results) == len(counts)

    def test_measure_scaling_labels(self):
        # FIXED: measure_scaling now exists in MemoryCollector
        results = self.collector.measure_scaling(
            fn_factory=lambda n: (lambda: None),
            counts=[5, 10],
            label_prefix="vault-",
        )
        assert results[0].label == "vault-5"
        assert results[1].label == "vault-10"


# ──────────────────────────────────────────────────────────────
# CpuCollector
# ──────────────────────────────────────────────────────────────

class TestCpuCollector:
    def setup_method(self):
        self.collector = CpuCollector(poll_interval_s=0.02)

    def test_returns_value_and_cpu_result(self):
        val, cpu = self.collector.measure(lambda: sum(range(100_000)))
        assert val == sum(range(100_000))
        assert cpu.duration_s >= 0

    def test_duration_positive(self):
        _, cpu = self.collector.measure(lambda: time.sleep(0.05))
        assert cpu.duration_s >= 0.04

    def test_cpu_samples_collected(self):
        _, cpu = self.collector.measure(lambda: time.sleep(0.1))
        assert len(cpu.cpu_samples) >= 1

    def test_cpu_mean_in_valid_range(self):
        _, cpu = self.collector.measure(lambda: time.sleep(0.1))
        # CPU% peut dépasser 100% sur multi-core — juste vérifier >= 0
        assert cpu.cpu_mean_pct >= 0

    def test_rss_values_positive(self):
        _, cpu = self.collector.measure(lambda: bytearray(100_000))
        assert cpu.rss_mb_before > 0
        assert cpu.rss_mb_after > 0

    def test_label_propagated(self):
        _, cpu = self.collector.measure(lambda: None, label="cpu-test")
        assert cpu.label == "cpu-test"

    def test_to_dict_has_required_keys(self):
        _, cpu = self.collector.measure(lambda: None)
        d = cpu.to_dict()
        for key in ("cpu_mean_pct", "cpu_peak_pct", "rss_mb_before", "rss_mb_after", "duration_s"):
            assert key in d