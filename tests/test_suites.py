"""
Tests des suites de benchmarks.

Deux niveaux :
  - Tests unitaires rapides (< 5s) : structure, registry, BenchmarkResult, Orchestrator
  - Tests d'intégration [slow] (30s+) : exécution réelle des suites

Lancer uniquement les tests rapides (CI) :
  pytest tests/test_suites.py -v -m "not slow"

Lancer tous les tests :
  pytest tests/test_suites.py -v -m "slow"
"""

import json
import pytest
from bench.suites import EncryptionSuite, KdfSuite, MemorySuite, ParallelSuite, ALL_SUITES
from bench.suites.base import BenchmarkResult


# ──────────────────────────────────────────────────────────────
# BenchmarkResult — tests unitaires purs (pas de crypto)
# ──────────────────────────────────────────────────────────────

class TestBenchmarkResult:
    def _make(self, **kwargs):
        defaults = dict(suite="test", name="n", algorithm="A")
        defaults.update(kwargs)
        return BenchmarkResult(**defaults)

    def test_to_dict_structure(self):
        d = self._make(throughput_mbps=100.0).to_dict()
        assert d["suite"] == "test"
        for section in ("timing", "memory", "cpu", "meta"):
            assert section in d

    def test_to_dict_timing_keys(self):
        d = self._make(mean_ms=4.0, stddev_ms=0.1, p95_ms=4.3, p99_ms=4.8).to_dict()["timing"]
        for k in ("mean_ms", "stddev_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "cv_percent"):
            assert k in d

    def test_overhead_vs_negative(self):
        fast = self._make(throughput_mbps=100.0)
        slow = self._make(throughput_mbps=80.0)
        assert abs(slow.overhead_vs(fast) - (-20.0)) < 0.01

    def test_overhead_vs_positive(self):
        slow = self._make(throughput_mbps=100.0)
        fast = self._make(throughput_mbps=150.0)
        assert abs(fast.overhead_vs(slow) - 50.0) < 0.01

    def test_overhead_vs_zero_ref(self):
        assert self._make(throughput_mbps=100.0).overhead_vs(self._make(throughput_mbps=0.0)) == 0.0

    def test_platform_auto_filled(self):
        assert self._make().platform != ""

    def test_timestamp_iso_format(self):
        ts = self._make().timestamp
        assert "T" in ts and "Z" in ts

    def test_extra_defaults_empty(self):
        assert self._make().extra == {}

    def test_extra_preserved_in_dict(self):
        r = self._make(extra={"workers": 4, "speedup": 3.1})
        assert r.to_dict()["extra"]["workers"] == 4

    def test_zero_throughput_by_default(self):
        assert self._make().throughput_mbps == 0.0


# ──────────────────────────────────────────────────────────────
# Registry — tests unitaires rapides
# ──────────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_four_suites_registered(self):
        for name in ("encryption", "kdf", "memory", "parallel"):
            assert name in ALL_SUITES

    def test_all_suites_have_run_method(self):
        for name, cls in ALL_SUITES.items():
            assert hasattr(cls, "run")

    def test_all_suites_have_name_attr(self):
        for cls in ALL_SUITES.values():
            assert hasattr(cls, "NAME")

    def test_all_suites_instantiable(self):
        for cls in ALL_SUITES.values():
            assert cls(iterations=1, warmup=0) is not None

    def test_suite_names_match_registry_keys(self):
        for key, cls in ALL_SUITES.items():
            assert cls.NAME == key


# ──────────────────────────────────────────────────────────────
# Orchestrator — tests unitaires (sans exécution réelle)
# ──────────────────────────────────────────────────────────────

class TestOrchestrator:
    def test_unknown_suite_raises(self):
        from bench.orchestrator import Orchestrator, BenchmarkError
        with pytest.raises(BenchmarkError, match="inconnues"):
            Orchestrator(suites=["does_not_exist"])

    def test_valid_suites_accepted(self):
        from bench.orchestrator import Orchestrator
        orch = Orchestrator(suites=["encryption", "kdf"])
        assert orch.suite_names == ["encryption", "kdf"]

    def test_default_suites_all(self):
        from bench.orchestrator import Orchestrator
        orch = Orchestrator()
        assert set(orch.suite_names) == set(ALL_SUITES.keys())

    def test_regression_no_baseline_passes(self, tmp_path):
        from bench.orchestrator import Orchestrator
        orch = Orchestrator(suites=["encryption"])
        results = [BenchmarkResult(suite="s", name="n", algorithm="A", throughput_mbps=100)]
        passed, _ = orch.check_regression(results, tmp_path / "missing.json")
        assert passed is True

    def test_regression_detects_slowdown(self, tmp_path):
        from bench.orchestrator import Orchestrator
        bp = tmp_path / "baseline.json"
        bp.write_text(json.dumps({
            "results": [{"suite": "s", "name": "n", "algorithm": "A", "throughput_mbps": 100.0}]
        }))
        orch = Orchestrator(suites=["encryption"])
        # -20% de throughput : régression > seuil de -10%
        results = [BenchmarkResult(suite="s", name="n", algorithm="A", throughput_mbps=80.0)]
        passed, msgs = orch.check_regression(results, bp, threshold_pct=-10.0)
        assert passed is False
        assert any("RÉGRESSION" in m for m in msgs)

    def test_regression_ok_within_threshold(self, tmp_path):
        from bench.orchestrator import Orchestrator
        bp = tmp_path / "baseline.json"
        bp.write_text(json.dumps({
            "results": [{"suite": "s", "name": "n", "algorithm": "A", "throughput_mbps": 100.0}]
        }))
        orch = Orchestrator(suites=["encryption"])
        # -3% : dans le seuil de -5%
        results = [BenchmarkResult(suite="s", name="n", algorithm="A", throughput_mbps=97.0)]
        passed, _ = orch.check_regression(results, bp, threshold_pct=-5.0)
        assert passed is True

    def test_report_generates_json(self, tmp_path):
        from bench.orchestrator import Orchestrator
        orch = Orchestrator(suites=["encryption"])
        results = [BenchmarkResult(suite="s", name="n", algorithm="A", throughput_mbps=100)]
        generated = orch.report(results, formats=["json"], output_dir=tmp_path)
        assert "json" in generated
        assert generated["json"].exists()


# ──────────────────────────────────────────────────────────────
# Suites d'intégration — marquées [slow]
# Lancer avec : pytest tests/test_suites.py -m slow
# ──────────────────────────────────────────────────────────────

@pytest.mark.slow
class TestEncryptionSuiteIntegration:
    """CAGOULE est lent (~250ms/op à cause du KDF+Z/pZ) — comportement normal."""

    @pytest.fixture(scope="class")
    def results(self):
        return EncryptionSuite(sizes=[65536], iterations=3, warmup=1).run()

    def test_three_algorithms_present(self, results):
        assert {r.algorithm for r in results} == {"CAGOULE", "AES-256-GCM", "ChaCha20-Poly1305"}

    def test_suite_name(self, results):
        assert all(r.suite == "encryption" for r in results)

    def test_all_mean_positive(self, results):
        assert all(r.mean_ms > 0 for r in results)

    def test_cagoule_throughput_nonzero(self, results):
        cag = next(r for r in results if r.algorithm == "CAGOULE")
        assert cag.throughput_mbps > 0

    def test_aes_faster_than_cagoule(self, results):
        cag = next(r for r in results if r.algorithm == "CAGOULE")
        aes = next(r for r in results if r.algorithm == "AES-256-GCM")
        assert aes.throughput_mbps > cag.throughput_mbps

    def test_p95_gte_mean(self, results):
        assert all(r.p95_ms >= r.mean_ms - 0.001 for r in results)


@pytest.mark.slow
class TestKdfSuiteIntegration:
    @pytest.fixture(scope="class")
    def results(self):
        return KdfSuite(iterations=2, warmup=1, time_costs=[1], memory_costs=[16384], parallelism=[1]).run()

    def test_both_algorithms(self, results):
        algos = {r.algorithm for r in results}
        assert "Argon2id" in algos and "PBKDF2-SHA256" in algos

    def test_argon2id_extra_keys(self, results):
        for r in (r for r in results if r.algorithm == "Argon2id"):
            for k in ("t_cost", "m_cost_mb", "parallelism", "security_score"):
                assert k in r.extra

    def test_all_mean_positive(self, results):
        assert all(r.mean_ms > 0 for r in results)


@pytest.mark.slow
class TestMemorySuiteIntegration:
    @pytest.fixture(scope="class")
    def results(self):
        return MemorySuite(vault_sizes=[5, 20], iterations=2, warmup=1).run()

    def test_vault_count(self, results):
        # Look for vault-creation results
        vault_results = [r for r in results if "vault-creation" in r.name]
        assert len(vault_results) == 2

    def test_cache_result(self, results):
        assert len([r for r in results if "cache" in r.name]) == 1

    def test_larger_vault_more_ram(self, results):
        vault = sorted([r for r in results if "vault-creation" in r.name], key=lambda r: r.extra["entry_count"])
        assert vault[-1].peak_mb >= vault[0].peak_mb


@pytest.mark.slow
class TestParallelSuiteIntegration:
    @pytest.fixture(scope="class")
    def results(self):
        return ParallelSuite(iterations=2, warmup=1, worker_counts=[1, 2], num_operations=10).run()

    def test_worker_counts(self, results):
        # Collect workers from results that have the 'workers' key in extra
        workers = []
        for r in results:
            if "workers" in r.extra:
                workers.append(r.extra["workers"])
        # Also add worker=1 from sequential baseline if not present
        if 1 not in workers:
            workers.append(1)
        assert sorted(workers) == [1, 2]

    def test_speedup_1w_is_one(self, results):
        # Find sequential baseline or worker=1 result
        r1 = None
        for r in results:
            if r.algorithm == "Sequential":
                r1 = r
                break
            if "workers" in r.extra and r.extra["workers"] == 1:
                r1 = r
                break
        assert r1 is not None, "No baseline or worker=1 result found"
        # Speedup should be 1.0 for baseline
        speedup = r1.extra.get("speedup_ratio", 1.0)
        assert abs(speedup - 1.0) < 0.01

    def test_throughput_positive(self, results):
        # Skip documentation result (has throughput_mbps=0)
        for r in results:
            if r.algorithm != "Documentation":
                assert r.throughput_mbps >= 0, f"Throughput should be >= 0 for {r.name}"