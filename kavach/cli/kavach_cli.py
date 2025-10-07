"""Console entrypoint for the Kavach hardening toolkit."""
from __future__ import annotations

import logging
from pathlib import Path

import click

from kavach.backend.app.core.checkpoint_manager import CheckpointManager
from kavach.backend.app.core.rule_engine import RuleEngine


PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_PATH = PACKAGE_ROOT / "examples" / "annexure_rules.json"


def _ensure_rules_path(path: Path) -> Path:
    if not path.exists():
        raise click.FileError(str(path), hint="Rules file not found")
    return path


@click.group()
def cli() -> None:
    """Kavach: A multi-platform system hardening tool."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@cli.command()
@click.option(
    "--rules-file",
    type=click.Path(path_type=Path),
    default=DEFAULT_RULES_PATH,
    show_default=True,
    help="Path to the annexure JSON file.",
)
@click.option(
    "--level",
    type=click.Choice(["basic", "moderate", "strict"]),
    default="basic",
    show_default=True,
    help="The hardening level to apply.",
)
@click.option("--dry-run", is_flag=True, help="Simulate changes without applying them.")
@click.option("--safe-mode", is_flag=True, help="Skip remediation/validation actions and only evaluate compliance.")
def apply(rules_file: Path, level: str, dry_run: bool, safe_mode: bool) -> None:
    """Apply hardening rules to the local system."""

    rules_path = _ensure_rules_path(rules_file)
    engine = RuleEngine(rules_file=str(rules_path), safe_mode=safe_mode)

    if not engine.ruleset:
        raise click.UsageError("No rules were loaded. Check the rules file contents.")

    click.echo(f"Loaded {sum(len(rs.rules) for rs in engine.ruleset)} rules from {rules_path}")
    click.echo(f"Applying level '{level}' (dry_run={dry_run}, safe_mode={safe_mode})")
    engine.apply_rules(level=level, dry_run=dry_run)
    click.echo("Rule application completed.")


@cli.command()
@click.argument("checkpoint_id")
def rollback(checkpoint_id: str) -> None:
    """Rollback the system to a previous checkpoint."""

    manager = CheckpointManager()
    record = manager.restore_checkpoint(checkpoint_id)
    if record is None:
        raise click.UsageError("Checkpoint not found or could not be decrypted.")

    click.echo("Checkpoint data loaded. TODO: apply rollback operations")


@cli.command()
def checkpoints() -> None:
    """List available checkpoints."""

    manager = CheckpointManager()
    ids = manager.list_checkpoints()
    if not ids:
        click.echo("No checkpoints available.")
        return

    for checkpoint_id in ids:
        record = manager.restore_checkpoint(checkpoint_id)
        if record is None:
            continue
        click.echo(f"{record.id} - {record.rule_id} @ {record.timestamp.isoformat()}")


@cli.command()
def start() -> None:
    """Start the TUI and Web UI."""

    from kavach.tui.app import KavachTUI

    app = KavachTUI()
    app.run()


@cli.command()
@click.option("--output", default="kavach-report.pdf", show_default=True, help="Output file for the report.")
def report(output: str) -> None:
    """Generate a compliance report."""

    click.echo("Report generation not yet implemented.")
    click.echo(f"Report would be saved to: {output}")


if __name__ == "__main__":
    cli()
