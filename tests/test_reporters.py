"""
Tests unitaires — Reporters.

Vérifie que chaque reporter génère un output valide
sans lever d'exception sur des données réalistes.
"""

import json
import csv
import tempfile
from pathlib import Path

import pytest
from bench.suites.base import BenchmarkResult
from bench.reporters import JsonReporter, CsvReporter, MarkdownReporter, HtmlReporter


def _make_results() -> list[BenchmarkResult]:
    """Jeu de données représentatif pour les tests."""
    shared = dict(
        data_size_bytes=1_048_576,
        iterations=100,
        warmup=10,
        mean_ms=4.08,
        stddev_ms=0.12,
        min_ms=3.89,
        max_ms=5.21,
        p95_ms=4.31,
        p99_ms=4.89,
        cv_percent=2.9,
        throughput_mbps=245.0,
        peak_mb=64.2,
        delta_mb=12.1,
    )
    return [
        BenchmarkResult(suite="encryption", name="encrypt-1MB", algorithm="CAGOULE", **shared),
        BenchmarkResult(suite="encryption", name="encrypt-1MB", algorithm="AES-256-GCM",
                        throughput_mbps=312.0, **{k: v for k, v in shared.items() if k != "throughput_mbps"}),
        BenchmarkResult(suite="encryption", name="encrypt-1MB", algorithm="ChaCha20-Poly1305",
                        throughput_mbps=298.0, **{k: v for k, v in shared.items() if k != "throughput_mbps"}),
        BenchmarkResult(suite="kdf", name="argon2id-t=3,m=64MB,p=2", algorithm="Argon2id",
                        mean_ms=187.0, stddev_ms=5.2, p95_ms=195.0, p99_ms=201.0,
                        min_ms=182.0, max_ms=205.0, peak_mb=64.0, delta_mb=64.0,
                        extra={"t_cost": 3, "m_cost_mb": 64, "parallelism": 2, "security_score": 19.3}),
        BenchmarkResult(suite="memory", name="vault-100-entries", algorithm="CAGOULE",
                        mean_ms=210.0, peak_mb=8.7,
                        extra={"entry_count": 100, "mb_per_entry": 0.087, "entries_per_sec": 476,
                               "fragmentation_pct": 4.1, "alloc_count": 850}),
        BenchmarkResult(suite="parallel", name="parallel-4w", algorithm="CAGOULE-ProcessPool",
                        mean_ms=1200.0, throughput_mbps=820.0,
                        cpu_mean_pct=320.0, cpu_peak_pct=395.0,
                        extra={"workers": 4, "speedup_ratio": 3.2, "parallel_efficiency_pct": 80.0,
                               "ops_per_sec": 166, "ctx_switches_voluntary": 12, "ctx_switches_involuntary": 4}),
    ]


# ──────────────────────────────────────────────────────────────
# JsonReporter
# ──────────────────────────────────────────────────────────────

class TestJsonReporter:
    def test_creates_valid_json(self, tmp_path):
        path = tmp_path / "bench.json"
        JsonReporter().report(_make_results(), path)
        data = json.loads(path.read_text())
        assert "results" in data
        assert "summary" in data
        assert "platform" in data
        assert "cagoule_bench_version" in data

    def test_result_count_matches(self, tmp_path):
        results = _make_results()
        path = tmp_path / "bench.json"
        JsonReporter().report(results, path)
        data = json.loads(path.read_text())
        assert len(data["results"]) == len(results)

    def test_timing_fields_present(self, tmp_path):
        path = tmp_path / "bench.json"
        JsonReporter().report(_make_results(), path)
        data = json.loads(path.read_text())
        r = data["results"][0]
        for key in ("mean_ms", "stddev_ms", "p95_ms", "p99_ms"):
            assert key in r["timing"]

    def test_summary_has_algorithms(self, tmp_path):
        path = tmp_path / "bench.json"
        JsonReporter().report(_make_results(), path)
        data = json.loads(path.read_text())
        assert "CAGOULE" in data["summary"]

    def test_platform_info_present(self, tmp_path):
        path = tmp_path / "bench.json"
        JsonReporter().report(_make_results(), path)
        data = json.loads(path.read_text())
        assert data["platform"]["python"] != ""


# ──────────────────────────────────────────────────────────────
# CsvReporter
# ──────────────────────────────────────────────────────────────

class TestCsvReporter:
    def test_creates_valid_csv(self, tmp_path):
        path = tmp_path / "bench.csv"
        CsvReporter().report(_make_results(), path)
        content = path.read_text()
        assert "algorithm" in content
        assert "throughput_mbps" in content

    def test_row_count_matches(self, tmp_path):
        results = _make_results()
        path = tmp_path / "bench.csv"
        CsvReporter().report(results, path)
        rows = list(csv.DictReader(path.read_text().splitlines()))
        assert len(rows) == len(results)

    def test_required_columns_present(self, tmp_path):
        path = tmp_path / "bench.csv"
        CsvReporter().report(_make_results(), path)
        reader = csv.DictReader(path.read_text().splitlines())
        cols = reader.fieldnames or []
        for col in ("suite", "name", "algorithm", "throughput_mbps", "mean_ms", "stddev_ms"):
            assert col in cols

    def test_cagoule_algo_in_csv(self, tmp_path):
        path = tmp_path / "bench.csv"
        CsvReporter().report(_make_results(), path)
        content = path.read_text()
        assert "CAGOULE" in content


# ──────────────────────────────────────────────────────────────
# MarkdownReporter
# ──────────────────────────────────────────────────────────────

class TestMarkdownReporter:
    def test_creates_markdown_file(self, tmp_path):
        path = tmp_path / "bench.md"
        MarkdownReporter().report(_make_results(), path)
        content = path.read_text()
        assert content.startswith("#")

    def test_contains_suite_headers(self, tmp_path):
        path = tmp_path / "bench.md"
        MarkdownReporter().report(_make_results(), path)
        content = path.read_text()
        assert "## ENCRYPTION" in content
        assert "## KDF" in content

    def test_contains_table_markers(self, tmp_path):
        path = tmp_path / "bench.md"
        MarkdownReporter().report(_make_results(), path)
        content = path.read_text()
        assert "|" in content  # table Markdown

    def test_overhead_section_present(self, tmp_path):
        path = tmp_path / "bench.md"
        MarkdownReporter().report(_make_results(), path)
        content = path.read_text()
        assert "Overhead" in content

    def test_cagoule_bold_in_table(self, tmp_path):
        path = tmp_path / "bench.md"
        MarkdownReporter().report(_make_results(), path)
        content = path.read_text()
        assert "**CAGOULE**" in content


# ──────────────────────────────────────────────────────────────
# HtmlReporter
# ──────────────────────────────────────────────────────────────

class TestHtmlReporter:
    def test_creates_html_file(self, tmp_path):
        path = tmp_path / "bench.html"
        HtmlReporter().report(_make_results(), path)
        content = path.read_text()
        assert "<!DOCTYPE html>" in content

    def test_chart_js_included(self, tmp_path):
        path = tmp_path / "bench.html"
        HtmlReporter().report(_make_results(), path)
        content = path.read_text()
        assert "chart.js" in content.lower()

    def test_chart_data_json_present(self, tmp_path):
        path = tmp_path / "bench.html"
        HtmlReporter().report(_make_results(), path)
        content = path.read_text()
        assert "const DATA = " in content

    def test_suite_sections_present(self, tmp_path):
        path = tmp_path / "bench.html"
        HtmlReporter().report(_make_results(), path)
        content = path.read_text()
        assert 'id="encryption"' in content
        assert 'id="kdf"' in content

    def test_cagoule_algo_in_html(self, tmp_path):
        path = tmp_path / "bench.html"
        HtmlReporter().report(_make_results(), path)
        assert "CAGOULE" in path.read_text()

    def test_file_size_reasonable(self, tmp_path):
        path = tmp_path / "bench.html"
        HtmlReporter().report(_make_results(), path)
        size_kb = path.stat().st_size / 1024
        # Dashboard HTML complet : entre 5 KB et 500 KB
        assert 5 < size_kb < 500
