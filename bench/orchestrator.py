"""
Orchestrator — cœur de cagoule-bench.

Responsabilités :
  - Découvrir et instancier les suites demandées
  - Appliquer les paramètres globaux (iterations, warmup, sizes)
  - Exécuter les suites dans l'ordre avec progress reporting
  - Collecter tous les BenchmarkResult
  - Dispatcher vers les reporters sélectionnés
  - Détecter les régressions de performance (mode CI)
"""

from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from bench.suites import ALL_SUITES
from bench.suites.base import BenchmarkResult
from bench.reporters import (
    ConsoleReporter,
    JsonReporter,
    CsvReporter,
    MarkdownReporter,
    HtmlReporter,
)

console = Console()

# Seuil de régression par défaut (CI)
REGRESSION_THRESHOLD_PCT = -5.0


class BenchmarkError(Exception):
    pass


class Orchestrator:
    """
    Point d'entrée central pour l'exécution des benchmarks.

    Usage:
        orch = Orchestrator(suites=["encryption", "kdf"], iterations=500)
        results = orch.run()
        orch.report(results, formats=["console", "json"], output_dir="./results")
    """

    def __init__(
        self,
        suites: list[str] | None = None,
        iterations: int = 500,
        warmup: int = 10,
        sizes: list[int] | None = None,
        parallel_workers: list[int] | None = None,
    ):
        self.suite_names = suites or list(ALL_SUITES.keys())
        self.iterations = iterations
        self.warmup = warmup
        self.sizes = sizes
        self.parallel_workers = parallel_workers

        # Validation
        unknown = [s for s in self.suite_names if s not in ALL_SUITES]
        if unknown:
            raise BenchmarkError(
                f"Suites inconnues : {unknown}. Disponibles : {list(ALL_SUITES.keys())}"
            )

    # ──────────────────────────────────────────────────────────
    # Exécution
    # ──────────────────────────────────────────────────────────

    def run(self, progress_callback: Callable[[str], None] | None = None) -> list[BenchmarkResult]:
        """
        Lance toutes les suites configurées.
        Retourne la liste complète des BenchmarkResult.
        """
        all_results: list[BenchmarkResult] = []
        t_start = time.perf_counter()

        console.print()
        console.rule("[bold blue]cagoule-bench v1.0.0[/bold blue]")
        console.print(
            f"  [dim]Plateforme :[/dim] [cyan]{platform.machine()}[/cyan]  "
            f"[dim]Python[/dim] [cyan]{platform.python_version()}[/cyan]  "
            f"[dim]Suites :[/dim] [cyan]{', '.join(self.suite_names)}[/cyan]"
        )
        console.print(
            f"  [dim]Iterations :[/dim] [yellow]{self.iterations}[/yellow]  "
            f"[dim]Warmup :[/dim] [yellow]{self.warmup}[/yellow]"
        )
        console.print()

        for suite_name in self.suite_names:
            suite_cls = ALL_SUITES[suite_name]

            # Instanciation avec paramètres adaptés à chaque suite
            kwargs: dict = {"iterations": self.iterations, "warmup": self.warmup}
            if suite_name == "encryption" and self.sizes:
                kwargs["sizes"] = self.sizes
            if suite_name == "parallel" and self.parallel_workers:
                kwargs["worker_counts"] = self.parallel_workers
            # KDF et Memory ont des iterations réduites par défaut
            if suite_name == "kdf":
                kwargs["iterations"] = min(self.iterations, 5)
                kwargs["warmup"] = 1
            if suite_name == "memory":
                kwargs["iterations"] = min(self.iterations, 3)
                kwargs["warmup"] = 1
            if suite_name == "parallel":
                kwargs["iterations"] = min(self.iterations, 3)
                kwargs["warmup"] = 1

            suite = suite_cls(**kwargs)

            with Progress(
                SpinnerColumn(),
                TextColumn(f"[bold cyan]{suite_name}[/bold cyan] [dim]{suite.DESCRIPTION}[/dim]"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("running", total=None)
                try:
                    results = suite.run()
                    progress.update(task, completed=True)
                except Exception as exc:
                    console.print(f"[red]✗ Suite '{suite_name}' a échoué : {exc}[/red]")
                    raise

            all_results.extend(results)
            console.print(
                f"  [green]✓[/green] [bold]{suite_name}[/bold] "
                f"— {len(results)} benchmarks"
            )

            if progress_callback:
                progress_callback(suite_name)

        elapsed = time.perf_counter() - t_start
        console.print()
        console.rule(
            f"[green]Terminé en {elapsed:.1f}s — {len(all_results)} résultats[/green]"
        )
        console.print()

        return all_results

    # ──────────────────────────────────────────────────────────
    # Reporting
    # ──────────────────────────────────────────────────────────

    def report(
        self,
        results: list[BenchmarkResult],
        formats: list[str] | None = None,
        output_dir: str | Path = "./benchmark_results",
    ) -> dict[str, Path]:
        """
        Génère les rapports dans les formats demandés.
        Retourne un dict {format: chemin_fichier}.
        """
        if not formats:
            formats = ["console"]

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        generated: dict[str, Path] = {}

        for fmt in formats:
            if fmt == "console":
                ConsoleReporter().report(results)
                generated["console"] = Path("<stdout>")

            elif fmt == "json":
                path = output_dir / f"bench_{ts}.json"
                JsonReporter().report(results, path)
                generated["json"] = path
                console.print(f"  [dim]→ JSON :[/dim] {path}")

            elif fmt == "csv":
                path = output_dir / f"bench_{ts}.csv"
                CsvReporter().report(results, path)
                generated["csv"] = path
                console.print(f"  [dim]→ CSV  :[/dim] {path}")

            elif fmt in ("md", "markdown"):
                path = output_dir / f"bench_{ts}.md"
                MarkdownReporter().report(results, path)
                generated["markdown"] = path
                console.print(f"  [dim]→ MD   :[/dim] {path}")

            elif fmt == "html":
                path = output_dir / f"bench_{ts}.html"
                HtmlReporter().report(results, path)
                generated["html"] = path
                console.print(f"  [dim]→ HTML :[/dim] {path}")

            else:
                console.print(f"[yellow]Format inconnu : {fmt} — ignoré[/yellow]")

        return generated

    # ──────────────────────────────────────────────────────────
    # Détection de régression (mode CI)
    # ──────────────────────────────────────────────────────────

    def check_regression(
        self,
        results: list[BenchmarkResult],
        baseline_path: str | Path,
        threshold_pct: float = REGRESSION_THRESHOLD_PCT,
    ) -> tuple[bool, list[str]]:
        """
        Compare les résultats actuels avec un baseline JSON.
        Retourne (passed: bool, messages: list[str]).

        Utilisé en CI/CD pour bloquer un merge si perf régresse > threshold_pct%.
        """
        baseline_path = Path(baseline_path)
        if not baseline_path.exists():
            return True, ["Pas de baseline — premier run, résultats sauvegardés."]

        baseline_data = json.loads(baseline_path.read_text())
        baseline_by_key = {
            f"{r['suite']}/{r['name']}/{r['algorithm']}": r
            for r in baseline_data.get("results", [])
        }

        regressions: list[str] = []
        ok_count = 0

        for r in results:
            key = f"{r.suite}/{r.name}/{r.algorithm}"
            baseline = baseline_by_key.get(key)
            if not baseline or r.throughput_mbps == 0:
                continue

            baseline_tp = baseline.get("throughput_mbps", 0)
            if baseline_tp == 0:
                continue

            delta_pct = (r.throughput_mbps - baseline_tp) / baseline_tp * 100
            if delta_pct < threshold_pct:
                regressions.append(
                    f"RÉGRESSION {key}: {baseline_tp:.1f} → {r.throughput_mbps:.1f} MB/s "
                    f"({delta_pct:+.1f}% < seuil {threshold_pct:+.0f}%)"
                )
            else:
                ok_count += 1

        passed = len(regressions) == 0
        summary = (
            [f"{ok_count} benchmarks OK, 0 régressions détectées."]
            if passed
            else regressions
        )
        return passed, summary
