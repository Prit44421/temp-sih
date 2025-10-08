"""Rule execution engine for Kavach."""
from __future__ import annotations

import importlib
import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from pydantic import ValidationError

from kavach.backend.app.core.checkpoint_manager import CheckpointManager, CheckpointRecord
from kavach.backend.app.core.logging_manager import get_logging_manager
from kavach.backend.app.core.os_detect import get_os_info
from kavach.backend.app.models.rules import Rule, RuleAction, RuleSet


logger = logging.getLogger(__name__)

LEVEL_PRIORITY: Dict[str, int] = {"basic": 0, "moderate": 1, "strict": 2}


@dataclass
class CommandResult:
    """Lightweight container for command execution results."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


class RuleEngine:
    """Load rule definitions and apply them to the current host."""

    def __init__(self, rules_file: str, *, safe_mode: bool = False) -> None:
        self.rules_file = Path(rules_file)
        self.safe_mode = safe_mode
        self.os_info = get_os_info()
        self.checkpoint_manager = CheckpointManager()
        self.logging_manager = get_logging_manager()
        self.ruleset: List[RuleSet] = self.load_rules()

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------
    def load_rules(self) -> List[RuleSet]:
        """Read rule definitions from ``self.rules_file``."""

        if not self.rules_file.exists():
            logger.error("Rules file not found at %s", self.rules_file)
            return []

        try:
            payload = json.loads(self.rules_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse rules file %s: %s", self.rules_file, exc)
            return []

        records: List[Dict[str, Any]] = []
        if isinstance(payload, list):
            records = payload
        elif isinstance(payload, dict):
            records = self._flatten_rules_payload(payload)
        else:
            logger.error(
                "Unsupported rules payload type %s in %s", type(payload).__name__, self.rules_file
            )
            return []

        rulesets: List[RuleSet] = []
        for record in records:
            try:
                rulesets.append(RuleSet.model_validate(record))
            except ValidationError as exc:
                logger.error("Invalid rule definition encountered: %s", exc)

        applicable_rulesets = [rs for rs in rulesets if self._is_platform_compatible(rs.os)]
        if len(applicable_rulesets) != len(rulesets):
            logger.info(
                "Filtered %s of %s rulesets for current platform", len(applicable_rulesets), len(rulesets)
            )

        logger.info(
            "Loaded %s rulesets (platform-filtered) from %s", len(applicable_rulesets), self.rules_file
        )
        return applicable_rulesets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def apply_rules(self, level: str = "basic", *, dry_run: bool = False) -> None:
        """Apply rules at ``level`` to the host."""

        if level not in LEVEL_PRIORITY:
            raise ValueError(f"Unsupported level '{level}'. Expected one of {tuple(LEVEL_PRIORITY)}")

        if not self.ruleset:
            logger.warning("No rules loaded; nothing to apply")
            return

        logger.info("Applying rules at level %s (dry_run=%s, safe_mode=%s)", level, dry_run, self.safe_mode)
        self.logging_manager.log_app_event("INFO", f"Starting rule application at level {level}")
        
        for ruleset in self.ruleset:
            if not self._is_platform_compatible(ruleset.os):
                logger.info("Skipping ruleset %s for OS %s", ruleset.module, ruleset.os)
                continue

            logger.info("Processing module %s (%s)", ruleset.module, ruleset.os)
            self.logging_manager.log_app_event("INFO", f"Processing module {ruleset.module} for {ruleset.os}")
            
            for rule in ruleset.rules:
                if not self._should_apply_rule(rule.level, level):
                    continue
                self._apply_single_rule(rule, dry_run=dry_run)
        
        self.logging_manager.log_app_event("INFO", f"Completed rule application at level {level}")

    def check_rule_compliance(self, rule: Rule) -> bool:
        """Check if a single rule is compliant."""
        check_result = self._execute_action(rule.check, phase="check")
        if not check_result.succeeded:
            return False

        expected = (rule.check.expect or "").strip()
        observed = check_result.stdout.strip()
        return expected and observed == expected

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _apply_single_rule(self, rule: Rule, *, dry_run: bool) -> None:
        logger.info("Evaluating rule %s - %s", rule.id, rule.title)
        
        # Execute check phase
        check_result = self._execute_action(rule.check, phase="check")
        self.logging_manager.log_rule_check(
            rule.id, 
            rule.check.cmd, 
            check_result.stdout, 
            check_result.stderr, 
            check_result.exit_code
        )
        
        if not check_result.succeeded:
            logger.warning(
                "Rule %s check returned non-zero exit code %s", rule.id, check_result.exit_code
            )

        expected = (rule.check.expect or "").strip()
        observed = check_result.stdout.strip()
        if expected and observed == expected:
            logger.info("Rule %s already compliant", rule.id)
            self.logging_manager.log_rule_event(
                level="INFO",
                rule_id=rule.id,
                action="check",
                status="compliant",
                message=f"Rule {rule.id} is already compliant"
            )
            return

        if dry_run:
            logger.info("Dry-run enabled; skipping remediation for %s", rule.id)
            self.logging_manager.log_rule_event(
                level="INFO",
                rule_id=rule.id,
                action="dry_run",
                status="skipped",
                message=f"Dry-run mode: skipping remediation for {rule.id}"
            )
            return

        # Create checkpoint before remediation
        checkpoint_id = self.checkpoint_manager.create_checkpoint(
            rule.id,
            {
                "stdout": check_result.stdout,
                "stderr": check_result.stderr,
                "exit_code": check_result.exit_code,
            },
        )
        self.logging_manager.log_checkpoint_created(checkpoint_id, rule.id)

        # Execute remediation phase
        remediate_result = self._execute_action(rule.remediate, phase="remediate")
        self.logging_manager.log_rule_remediate(
            rule.id,
            rule.remediate.cmd,
            remediate_result.stdout,
            remediate_result.stderr,
            remediate_result.exit_code
        )
        
        if not remediate_result.succeeded:
            logger.error(
                "Remediation for rule %s failed with exit code %s: %s",
                rule.id,
                remediate_result.exit_code,
                remediate_result.stderr.strip(),
            )
            self._attempt_rollback(checkpoint_id)
            return

        # Execute validation phase
        validate_result = self._execute_action(rule.validate, phase="validate")
        validate_expected = (rule.validate.expect or "").strip()
        validation_passed = validate_result.succeeded and (not validate_expected or validate_result.stdout.strip() == validate_expected)
        
        self.logging_manager.log_rule_validate(
            rule.id,
            rule.validate.cmd,
            validate_result.stdout,
            validate_result.stderr,
            validate_result.exit_code,
            validate_expected
        )
        
        if not validation_passed:
            logger.error(
                "Validation for rule %s failed (exit=%s, stdout=%r)",
                rule.id,
                validate_result.exit_code,
                validate_result.stdout.strip(),
            )
            self._attempt_rollback(checkpoint_id)
            return

        logger.info("Rule %s applied successfully", rule.id)
        self.logging_manager.log_rule_event(
            level="INFO",
            rule_id=rule.id,
            action="complete",
            status="success",
            message=f"Rule {rule.id} applied and validated successfully"
        )

    def _execute_action(self, action: RuleAction, *, phase: str) -> CommandResult:
        """Execute a rule action and return its result."""

        if self.safe_mode and phase in {"remediate", "validate"}:
            logger.info("Safe mode active; skipping %s action", phase)
            return CommandResult(exit_code=0, stdout="", stderr="")

        try:
            if action.type == "shell":
                result = subprocess.run(
                    action.cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            elif action.type == "powershell":
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", action.cmd],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            elif action.type == "python":
                stdout, stderr, exit_code = self._execute_python_callable(action.cmd)
                return CommandResult(exit_code=exit_code, stdout=stdout, stderr=stderr)
            else:
                raise ValueError(f"Unsupported action type: {action.type}")

            return CommandResult(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except FileNotFoundError as exc:
            logger.error("Command not found for action %s: %s", action.type, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Unexpected error executing action %s: %s", action.type, exc)

        return CommandResult(exit_code=-1, stdout="", stderr="execution error")

    def _execute_python_callable(self, dotted_path: str) -> tuple[str, str, int]:
        """Execute a Python callable referenced by dotted path."""

        module_path, _, attr = dotted_path.rpartition(":")
        if not module_path:
            raise ValueError("Python rule actions must be in 'module:callable' format")

        module = importlib.import_module(module_path)
        func = getattr(module, attr)
        if not callable(func):
            raise TypeError(f"Referenced object {dotted_path} is not callable")

        try:
            result = func()
            stdout = json.dumps(result) if isinstance(result, (dict, list)) else str(result or "")
            return stdout, "", 0
        except Exception as exc:  # pragma: no cover - delegated logic
            logger.exception("Python callable %s raised an error: %s", dotted_path, exc)
            return "", str(exc), 1

    def _attempt_rollback(self, checkpoint_id: str) -> None:
        record: CheckpointRecord | None = self.checkpoint_manager.restore_checkpoint(checkpoint_id)
        if record is None:
            logger.error("Rollback failed; checkpoint %s could not be restored", checkpoint_id)
            self.logging_manager.log_rollback_attempt(checkpoint_id, "unknown", False)
            return

        # TODO: Implement actual rollback logic leveraging ``record.data``.
        logger.warning("Rollback required for checkpoint %s; action not yet implemented", checkpoint_id)
        self.logging_manager.log_rollback_attempt(checkpoint_id, record.rule_id, False)

    def _should_apply_rule(self, rule_level: str, target_level: str) -> bool:
        return LEVEL_PRIORITY[rule_level] <= LEVEL_PRIORITY[target_level]

    def _is_platform_compatible(self, target_os: str) -> bool:
        system = (self.os_info.get("system") or "").lower()
        distro_id = (self.os_info.get("distro_id") or "").lower()

        if "windows" in system and "windows" in target_os.lower():
            return True
        if "linux" in system and target_os.lower() in {distro_id, "linux"}:
            return True
        return False

    def _flatten_rules_payload(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalise nested OS→module→rules payloads into RuleSet dictionaries."""

        flattened: List[Dict[str, Any]] = []

        for os_name, os_block in payload.items():
            if not isinstance(os_block, dict):
                logger.warning("Skipping OS entry %r: expected object, got %s", os_name, type(os_block).__name__)
                continue

            modules_obj = os_block.get("modules") if "modules" in os_block else os_block
            if not isinstance(modules_obj, dict):
                logger.warning(
                    "Skipping OS entry %r: modules should be an object, got %s",
                    os_name,
                    type(modules_obj).__name__,
                )
                continue

            for module_name, module_payload in modules_obj.items():
                if module_name == "modules":
                    # Prevent infinite loops if structure nests modules key one level deeper without data.
                    continue

                rules_payload: Any
                if isinstance(module_payload, dict) and "rules" in module_payload:
                    rules_payload = module_payload.get("rules")
                else:
                    rules_payload = module_payload

                if not isinstance(rules_payload, list):
                    logger.warning(
                        "Skipping module %r under %r: expected list of rules, got %s",
                        module_name,
                        os_name,
                        type(rules_payload).__name__,
                    )
                    continue

                flattened.append({
                    "os": str(os_name),
                    "module": str(module_name),
                    "rules": rules_payload,
                })

        return flattened


__all__ = ["RuleEngine", "CommandResult"]

