"""Textual-based terminal UI for managing Kavach runs."""
from __future__ import annotations

import asyncio
import secrets
import string
import threading
from pathlib import Path
from typing import Dict

import uvicorn
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Static

from kavach.backend.app.core.checkpoint_manager import CheckpointManager
from kavach.backend.app.core.logging_manager import setup_logging
from kavach.backend.app.core.rule_engine import RuleEngine
from kavach.backend.app.main import app as fastapi_app


ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_PATH = ROOT_DIR / "examples" / "annexure_rules.json"
CSS_PATH = Path(__file__).with_name("app.css")


def _generate_token(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class KavachTUI(App):
    """Interactive terminal client for Kavach."""

    CSS_PATH = CSS_PATH
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "toggle_dark", "Toggle dark mode"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.web_ui_token = _generate_token()
        setup_logging()  # Initialize structured logging
        self.rule_engine = RuleEngine(str(RULES_PATH))
        self.checkpoint_manager = CheckpointManager()
        self._web_server_thread: threading.Thread | None = None
        self._rule_status: Dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

        with Horizontal(id="layout"):
            with Vertical(id="sidebar"):
                yield Static("Kavach Control", id="title")
                yield Button("Apply Basic", id="apply_basic", variant="success")
                yield Button("Apply Moderate", id="apply_moderate", variant="primary")
                yield Button("Apply Strict", id="apply_strict", variant="warning")
                yield Button("Rollback Latest", id="rollback", variant="error")
                yield Button("Generate Report", id="report")
            with Vertical(id="content"):
                yield Static("Welcome to Kavach", id="welcome")
                yield Static("Press a button to begin", id="status_message")
                yield Static("", id="token_display")
                yield DataTable(id="rules_table")

    def on_mount(self) -> None:  # type: ignore[override]
        table = self.query_one(DataTable)
        table.add_columns("Rule ID", "Title", "Level", "Status")
        self._refresh_rule_table()
        self._start_web_ui()

    def _refresh_rule_table(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        for ruleset in self.rule_engine.ruleset:
            for rule in ruleset.rules:
                status = self._rule_status.get(rule.id, "Not applied")
                table.add_row(rule.id, rule.title, rule.level, status)

    def _start_web_ui(self) -> None:
        if self._web_server_thread and self._web_server_thread.is_alive():
            return

        config = uvicorn.Config(fastapi_app, host="127.0.0.1", port=8000, log_level="info")
        server = uvicorn.Server(config)

        def run_server() -> None:
            fastapi_app.state.token = self.web_ui_token
            asyncio.run(server.serve())

        self._web_server_thread = threading.Thread(target=run_server, daemon=True)
        self._web_server_thread.start()

        token_message = (
            f"Web UI available at http://127.0.0.1:8000/ui\n"
            f"Access token: {self.web_ui_token}"
        )
        self.query_one("#token_display", Static).update(token_message)

    async def on_button_pressed(self, event: Button.Pressed) -> None:  # type: ignore[override]
        button_id = event.button.id
        if button_id in {"apply_basic", "apply_moderate", "apply_strict"}:
            level = button_id.split("_")[-1]
            await self._handle_apply(level)
        elif button_id == "rollback":
            await self._handle_rollback()
        elif button_id == "report":
            self.query_one("#status_message", Static).update("Report generation not yet implemented")

    async def _handle_apply(self, level: str) -> None:
        self.query_one("#status_message", Static).update(f"Applying {level} rules...")
        self.rule_engine.apply_rules(level=level)
        for ruleset in self.rule_engine.ruleset:
            for rule in ruleset.rules:
                if rule.level == level:
                    self._rule_status[rule.id] = "Applied"
        self._refresh_rule_table()
        self.query_one("#status_message", Static).update(f"Completed {level} rule execution")

    async def _handle_rollback(self) -> None:
        checkpoints = self.checkpoint_manager.list_checkpoints()
        if not checkpoints:
            self.query_one("#status_message", Static).update("No checkpoints available for rollback")
            return

        latest = checkpoints[-1]
        record = self.checkpoint_manager.restore_checkpoint(latest)
        if record is None:
            self.query_one("#status_message", Static).update("Failed to load checkpoint")
            return

        self.query_one("#status_message", Static).update(
            f"Loaded checkpoint {record.id}. Manual rollback required."
        )


if __name__ == "__main__":
    KavachTUI().run()
