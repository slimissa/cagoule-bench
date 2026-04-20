"""
cagoule-bench CLI — interface Click.

Commandes :
  run      Exécute une ou plusieurs suites
  compare  Compare CAGOULE avec AES-256-GCM sur une taille donnée
  watch    Monitoring continu (intervalle fixe)
  ci       Mode CI/CD : exécute + compare au baseline, exit code 1 si régression
"""

import sys
import time
from pathlib import Path

import click
from rich.console import Console

from bench.orchestrator import Orchestrator, BenchmarkError
from bench.reporters.data_reporters import JsonReporter

console = Console()

VALID_SUITES = ["encryption", "kdf", "memory", "parallel"]
VALID_FORMATS = ["console", "json", "csv", "md", "html"]


# ──────────────────────────────────────────────────────────────
# Groupe principal
# ──────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="cagoule-bench")
def main():
    """
    cagoule-bench — Suite de Benchmarking Cryptographique pour CAGOULE.

    \b
    Exemples rapides :
      cagoule-bench run
      cagoule-bench run --suite encryption --iterations 1000
      cagoule-bench run --suite encryption --suite kdf --format html --output ./results
      cagoule-bench compare --size 1048576
      cagoule-bench watch --interval 60 --duration 3600
      cagoule-bench ci --baseline ./results/baseline.json
    """


# ──────────────────────────────────────────────────────────────
# run
# ──────────────────────────────────────────────────────────────

@main.command()
@click.option(
    "--suite", "-s",
    multiple=True,
    type=click.Choice(VALID_SUITES),
    help="Suite(s) à exécuter. Peut être répété. Par défaut : toutes.",
)
@click.option("--iterations", "-n", default=500, show_default=True, help="Itérations par benchmark.")
@click.option("--warmup", "-w", default=10, show_default=True, help="Itérations de warmup.")
@click.option(
    "--format", "-f", "formats",
    multiple=True,
    type=click.Choice(VALID_FORMATS),
    default=("console",),
    show_default=True,
    help="Format(s) de sortie. Peut être répété.",
)
@click.option("--output", "-o", default="./benchmark_results", show_default=True, help="Dossier de sortie.")
@click.option(
    "--size", "sizes",
    multiple=True,
    type=int,
    help="Taille(s) de message en bytes (suite encryption). Ex: --size 1024 --size 1048576",
)
@click.option(
    "--workers", "parallel_workers",
    multiple=True,
    type=int,
    help="Nombre(s) de workers (suite parallel). Ex: --workers 1 --workers 4 --workers 8",
)
def run(suite, iterations, warmup, formats, output, sizes, parallel_workers):
    """
    Exécute les suites de benchmarks.

    \b
    Exemples :
      cagoule-bench run
      cagoule-bench run --suite encryption --suite kdf
      cagoule-bench run --suite encryption -n 1000 -f console -f html -o ./results
      cagoule-bench run --suite encryption --size 1024 --size 65536 --size 1048576
    """
    try:
        orch = Orchestrator(
            suites=list(suite) or None,
            iterations=iterations,
            warmup=warmup,
            sizes=list(sizes) or None,
            parallel_workers=list(parallel_workers) or None,
        )
        results = orch.run()
        orch.report(results, formats=list(formats), output_dir=output)

    except BenchmarkError as e:
        console.print(f"[red]Erreur : {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interruption utilisateur.[/yellow]")
        sys.exit(0)


# ──────────────────────────────────────────────────────────────
# compare
# ──────────────────────────────────────────────────────────────

@main.command()
@click.option("--size", "-s", default=1_048_576, show_default=True, help="Taille du message en bytes.")
@click.option("--iterations", "-n", default=1000, show_default=True)
@click.option("--warmup", "-w", default=10, show_default=True)
@click.option(
    "--format", "-f", "formats",
    multiple=True,
    type=click.Choice(VALID_FORMATS),
    default=("console",),
)
@click.option("--output", "-o", default="./benchmark_results", show_default=True)
def compare(size, iterations, warmup, formats, output):
    """
    Compare CAGOULE vs AES-256-GCM vs ChaCha20-Poly1305 sur une taille donnée.

    \b
    Exemples :
      cagoule-bench compare
      cagoule-bench compare --size 65536 -f html -o ./results
      cagoule-bench compare --size 10485760 -n 200
    """
    size_label = _fmt_bytes(size)
    console.print(f"\n[bold cyan]Mode Compare — taille : {size_label}[/bold cyan]\n")

    try:
        orch = Orchestrator(
            suites=["encryption"],
            iterations=iterations,
            warmup=warmup,
            sizes=[size],
        )
        results = orch.run()
        orch.report(results, formats=list(formats), output_dir=output)

    except BenchmarkError as e:
        console.print(f"[red]Erreur : {e}[/red]")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────
# watch
# ──────────────────────────────────────────────────────────────

@main.command()
@click.option("--interval", default=60, show_default=True, help="Intervalle en secondes entre chaque run.")
@click.option("--duration", default=3600, show_default=True, help="Durée totale de monitoring en secondes.")
@click.option(
    "--suite", "-s",
    multiple=True,
    type=click.Choice(VALID_SUITES),
    default=("encryption",),
    show_default=True,
)
@click.option("--output", "-o", default="./benchmark_results/watch", show_default=True)
def watch(interval, duration, suite, output):
    """
    Monitoring continu : exécute les benchmarks toutes les N secondes.

    Utile pour détecter une dérive de performance dans le temps.
    Chaque run génère un fichier JSON horodaté dans le dossier output.

    \b
    Exemples :
      cagoule-bench watch
      cagoule-bench watch --interval 30 --duration 600 --suite encryption
    """
    console.print(f"\n[bold cyan]Mode Watch — interval={interval}s, duration={duration}s[/bold cyan]")
    console.print("[dim]Ctrl+C pour arrêter[/dim]\n")

    t_end = time.time() + duration
    run_count = 0

    try:
        while time.time() < t_end:
            run_count += 1
            console.print(f"[bold]Run #{run_count}[/bold] — {time.strftime('%H:%M:%S')}")
            try:
                orch = Orchestrator(
                    suites=list(suite),
                    iterations=200,
                    warmup=5,
                )
                results = orch.run()
                orch.report(results, formats=["json"], output_dir=output)
            except Exception as exc:
                console.print(f"[red]Run #{run_count} échoué : {exc}[/red]")

            remaining = t_end - time.time()
            if remaining <= 0:
                break
            sleep_time = min(interval, remaining)
            console.print(f"[dim]Prochain run dans {sleep_time:.0f}s...[/dim]\n")
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        console.print(f"\n[yellow]Watch arrêté après {run_count} runs.[/yellow]")


# ──────────────────────────────────────────────────────────────
# ci
# ──────────────────────────────────────────────────────────────

@main.command()
@click.option(
    "--baseline", "-b",
    default="./benchmark_results/baseline.json",
    show_default=True,
    help="Chemin vers le fichier baseline JSON.",
)
@click.option("--threshold", default=-5.0, show_default=True, help="Seuil de régression en % (ex: -5.0).")
@click.option(
    "--suite", "-s",
    multiple=True,
    type=click.Choice(VALID_SUITES),
    default=("encryption",),
)
@click.option("--save-baseline", is_flag=True, default=False, help="Sauvegarder ce run comme nouveau baseline.")
@click.option("--output", "-o", default="./benchmark_results", show_default=True)
def ci(baseline, threshold, suite, save_baseline, output):
    """
    Mode CI/CD : exécute les benchmarks et compare au baseline.

    Exit code 0 si OK, exit code 1 si régression détectée.
    Parfait pour GitHub Actions.

    \b
    Exemples :
      cagoule-bench ci
      cagoule-bench ci --baseline ./results/baseline.json --threshold -10
      cagoule-bench ci --save-baseline   # premier run : crée le baseline
    """
    console.print(f"\n[bold cyan]Mode CI — baseline : {baseline}[/bold cyan]\n")

    try:
        orch = Orchestrator(
            suites=list(suite),
            iterations=300,
            warmup=5,
        )
        results = orch.run()

        # Sauvegarde baseline si demandé
        if save_baseline:
            baseline_path = Path(baseline)
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            JsonReporter().report(results, baseline_path)
            console.print(f"[green]✓ Baseline sauvegardé : {baseline_path}[/green]")
            sys.exit(0)

        # Vérification régression
        passed, messages = orch.check_regression(results, baseline, threshold)

        if passed:
            for msg in messages:
                console.print(f"[green]✓ {msg}[/green]")
            sys.exit(0)
        else:
            console.print("[red bold]✗ RÉGRESSIONS DÉTECTÉES[/red bold]")
            for msg in messages:
                console.print(f"[red]  {msg}[/red]")
            sys.exit(1)

    except BenchmarkError as e:
        console.print(f"[red]Erreur : {e}[/red]")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1_048_576:
        return f"{n // 1024} KB"
    return f"{n // 1_048_576} MB"


if __name__ == "__main__":
    main()
