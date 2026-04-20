"""
ConsoleReporter — affichage rich dans le terminal.

Génère des tables colorées avec statuts visuels.
Affiche aussi les overheads CAGOULE vs standards.
"""

import platform
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from bench.suites.base import BenchmarkResult

console = Console()


def _overhead_str(cagoule_tp: float, ref_tp: float) -> str:
    if ref_tp == 0:
        return "N/A"
    pct = (cagoule_tp - ref_tp) / ref_tp * 100
    sign = "+" if pct > 0 else ""
    color = "green" if pct >= 0 else "red"
    return f"[{color}]{sign}{pct:.1f}%[/{color}]"


class ConsoleReporter:
    def report(self, results: list[BenchmarkResult], suite_name: str = "") -> None:
        # ── Header ───────────────────────────────────────────
        console.print()
        console.print(Panel(
            Text.assemble(
                ("cagoule-bench ", "bold cyan"),
                ("v1.0.0", "bold white"),
                ("  |  ", "dim"),
                (platform.machine(), "yellow"),
                ("  |  ", "dim"),
                (platform.python_version(), "yellow"),
                ("  |  ", "dim"),
                (time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "dim"),
            ),
            title="[bold blue]CAGOULE-BENCH[/bold blue]",
            border_style="blue",
        ))

        if not results:
            console.print("[yellow]Aucun résultat à afficher.[/yellow]")
            return

        suites = {r.suite for r in results}
        for suite in sorted(suites):
            suite_results = [r for r in results if r.suite == suite]
            self._render_suite(suite, suite_results)

    def _render_suite(self, suite: str, results: list[BenchmarkResult]) -> None:
        console.print(f"\n[bold cyan]{'━'*70}[/bold cyan]")
        console.print(f"[bold white]  {suite.upper()} SUITE[/bold white]")
        console.print(f"[bold cyan]{'━'*70}[/bold cyan]")

        if suite == "encryption":
            self._render_encryption(results)
        elif suite == "kdf":
            self._render_kdf(results)
        elif suite == "memory":
            self._render_memory(results)
        elif suite == "parallel":
            self._render_parallel(results)
        else:
            self._render_generic(results)

    def _render_encryption(self, results: list[BenchmarkResult]) -> None:
        t = Table(box=box.ROUNDED, border_style="blue", header_style="bold blue on black")
        t.add_column("Test", style="white", min_width=20)
        t.add_column("Algorithm", style="cyan", min_width=16)
        t.add_column("Throughput", justify="right", style="green")
        t.add_column("Mean (ms)", justify="right")
        t.add_column("Stddev", justify="right", style="dim")
        t.add_column("p95 (ms)", justify="right", style="dim")
        t.add_column("Mem Peak", justify="right", style="yellow")

        for r in results:
            alg_style = "bold green" if r.algorithm == "CAGOULE" else "white"
            t.add_row(
                r.name,
                f"[{alg_style}]{r.algorithm}[/{alg_style}]",
                f"{r.throughput_mbps:.1f} MB/s",
                f"{r.mean_ms:.3f}",
                f"±{r.stddev_ms:.3f}",
                f"{r.p95_ms:.3f}",
                f"{r.peak_mb:.2f} MB",
            )

        console.print(t)

        # Overhead analysis
        console.print("\n[bold]Overhead Analysis — CAGOULE vs standards[/bold]")
        by_test: dict[str, dict] = {}
        for r in results:
            key = r.name
            if key not in by_test:
                by_test[key] = {}
            by_test[key][r.algorithm] = r.throughput_mbps

        ot = Table(box=box.SIMPLE, border_style="dim")
        ot.add_column("Test", style="white")
        ot.add_column("vs AES-256-GCM", justify="right")
        ot.add_column("vs ChaCha20-Poly1305", justify="right")

        for name, algos in sorted(by_test.items()):
            cag = algos.get("CAGOULE", 0)
            aes = algos.get("AES-256-GCM", 0)
            cha = algos.get("ChaCha20-Poly1305", 0)
            ot.add_row(name, _overhead_str(cag, aes), _overhead_str(cag, cha))

        console.print(ot)

    def _render_kdf(self, results: list[BenchmarkResult]) -> None:
        argon_results = [r for r in results if r.algorithm == "Argon2id"]
        pbkdf2_results = [r for r in results if r.algorithm == "PBKDF2-SHA256"]

        if argon_results:
            console.print("\n[bold cyan]Argon2id Parameter Grid[/bold cyan]")
            t = Table(box=box.ROUNDED, border_style="blue", header_style="bold blue on black")
            t.add_column("t_cost", justify="center")
            t.add_column("m_cost", justify="center")
            t.add_column("p", justify="center")
            t.add_column("Mean (ms)", justify="right", style="green")
            t.add_column("Stddev", justify="right", style="dim")
            t.add_column("Peak RAM", justify="right", style="yellow")
            t.add_column("Security Score", justify="center")
            for r in argon_results:
                ex = r.extra
                score = ex.get("security_score", 0)
                score_color = "green" if score > 20 else ("yellow" if score > 16 else "red")
                t.add_row(
                    str(ex.get("t_cost")),
                    f"{ex.get('m_cost_mb')} MB",
                    str(ex.get("parallelism")),
                    f"{r.mean_ms:.1f}",
                    f"±{r.stddev_ms:.1f}",
                    f"{r.peak_mb:.1f} MB",
                    f"[{score_color}]{score}[/{score_color}]",
                )
            console.print(t)

        if pbkdf2_results:
            console.print("\n[bold cyan]PBKDF2-SHA256 Comparison[/bold cyan]")
            t2 = Table(box=box.ROUNDED, border_style="dim", header_style="bold dim")
            t2.add_column("Iterations", justify="right")
            t2.add_column("Mean (ms)", justify="right")
            t2.add_column("Security Score", justify="center")
            for r in pbkdf2_results:
                ex = r.extra
                t2.add_row(
                    f"{ex.get('iterations', 0):,}",
                    f"{r.mean_ms:.1f}",
                    str(ex.get("security_score", 0)),
                )
            console.print(t2)

    def _render_memory(self, results: list[BenchmarkResult]) -> None:
        vault_results = [r for r in results if "entries" in r.name]
        cache_results = [r for r in results if "cache" in r.name]

        if vault_results:
            t = Table(box=box.ROUNDED, border_style="blue", header_style="bold blue on black")
            t.add_column("Vault Size", justify="right")
            t.add_column("Peak RAM", justify="right", style="yellow")
            t.add_column("MB/entry", justify="right")
            t.add_column("Build Time", justify="right", style="green")
            t.add_column("Entries/s", justify="right")
            t.add_column("Fragmentation", justify="right", style="dim")
            for r in vault_results:
                ex = r.extra
                t.add_row(
                    f"{ex.get('entry_count'):,} entries",
                    f"{r.peak_mb:.2f} MB",
                    f"{ex.get('mb_per_entry', 0):.4f}",
                    f"{r.mean_ms:.1f} ms",
                    f"{ex.get('entries_per_sec', 0):.0f}",
                    f"{ex.get('fragmentation_pct', 0):.1f}%",
                )
            console.print(t)

        if cache_results:
            for r in cache_results:
                ex = r.extra
                console.print(
                    f"\n[bold]Cache Analysis (1MB)[/bold]  "
                    f"Cold: [red]{ex.get('cold_ms', 0):.2f}ms[/red]  "
                    f"Hot: [green]{ex.get('hot_ms', 0):.2f}ms[/green]  "
                    f"Speedup: [bold cyan]{ex.get('cache_speedup', 0):.1f}x[/bold cyan]"
                )

    def _render_parallel(self, results: list[BenchmarkResult]) -> None:
        t = Table(box=box.ROUNDED, border_style="blue", header_style="bold blue on black")
        t.add_column("Workers", justify="center")
        t.add_column("Throughput", justify="right", style="green")
        t.add_column("Ops/s", justify="right")
        t.add_column("Speedup", justify="right", style="cyan")
        t.add_column("Efficiency", justify="right")
        t.add_column("CPU Mean", justify="right", style="yellow")
        t.add_column("CPU Peak", justify="right", style="yellow")
        for r in results:
            ex = r.extra
            speedup = ex.get("speedup_ratio", 1.0)
            eff = ex.get("parallel_efficiency_pct", 0)
            eff_color = "green" if eff > 70 else ("yellow" if eff > 40 else "red")
            t.add_row(
                str(ex.get("workers")),
                f"{r.throughput_mbps:.1f} MB/s",
                f"{ex.get('ops_per_sec', 0):.0f}",
                f"{speedup:.2f}x",
                f"[{eff_color}]{eff:.1f}%[/{eff_color}]",
                f"{r.cpu_mean_pct:.1f}%",
                f"{r.cpu_peak_pct:.1f}%",
            )
        console.print(t)
        console.print("[dim]Note: ProcessPoolExecutor — GIL non-impactant pour chiffrement CPU-bound[/dim]")

    def _render_generic(self, results: list[BenchmarkResult]) -> None:
        t = Table(box=box.ROUNDED, border_style="blue", header_style="bold blue on black")
        t.add_column("Name")
        t.add_column("Algorithm")
        t.add_column("Mean (ms)", justify="right")
        t.add_column("Throughput", justify="right")
        for r in results:
            t.add_row(r.name, r.algorithm, f"{r.mean_ms:.3f}", f"{r.throughput_mbps:.1f} MB/s")
        console.print(t)
