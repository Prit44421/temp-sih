"""FastAPI endpoints exposed by the Kavach backend."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from kavach.backend.app.core.checkpoint_manager import CheckpointManager
from kavach.backend.app.core.os_detect import get_os_info
from kavach.backend.app.core.rule_engine import RuleEngine
from kavach.backend.app.models.rules import RuleSet


router = APIRouter()

_DEFAULT_RULES_PATH = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "annexure_rules.json"
)
_RULES_FILE = Path(os.getenv("KAVACH_RULES_FILE", str(_DEFAULT_RULES_PATH)))

_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
if not _RULES_FILE.exists() and _DEFAULT_RULES_PATH.exists():
    _RULES_FILE.write_text(_DEFAULT_RULES_PATH.read_text(encoding="utf-8"), encoding="utf-8")

_checkpoint_manager = CheckpointManager()
_rule_engine = RuleEngine(str(_RULES_FILE))


class ApplyRequest(BaseModel):
    level: Literal["basic", "moderate", "strict"] = "basic"
    dry_run: bool = False


class ApplyResponse(BaseModel):
    message: str


class CheckpointSummary(BaseModel):
    id: str
    rule_id: str
    timestamp: str


@router.get("/status")
def get_status() -> dict:
    """Expose host OS information."""

    return {"status": "ok", "system_info": get_os_info()}


@router.get("/checkpoints", response_model=List[CheckpointSummary])
def list_checkpoints() -> List[CheckpointSummary]:
    """Return stored checkpoints with metadata."""

    summaries: List[CheckpointSummary] = []
    for checkpoint_id in _checkpoint_manager.list_checkpoints():
        record = _checkpoint_manager.restore_checkpoint(checkpoint_id)
        if record is None:
            continue
        summaries.append(
            CheckpointSummary(
                id=record.id,
                rule_id=record.rule_id,
                timestamp=record.timestamp.isoformat(),
            )
        )
    return summaries


@router.delete("/checkpoints/{checkpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_checkpoint(checkpoint_id: str) -> None:
    """Remove a checkpoint from disk."""

    deleted = _checkpoint_manager.delete_checkpoint(checkpoint_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checkpoint not found")


@router.post("/apply", response_model=ApplyResponse, status_code=status.HTTP_202_ACCEPTED)
def apply_rules(request: ApplyRequest) -> ApplyResponse:
    """Apply rules at the requested level."""

    _rule_engine.apply_rules(level=request.level, dry_run=request.dry_run)
    return ApplyResponse(message=f"Rule application triggered at level {request.level}")


@router.post("/rollback/{checkpoint_id}")
def rollback_checkpoint(checkpoint_id: str) -> dict:
    """Trigger a rollback using the specified checkpoint."""

    record = _checkpoint_manager.restore_checkpoint(checkpoint_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checkpoint not found")

    # TODO: Implement actual rollback logic once remediation artefacts are tracked.
    return {
        "message": f"Rollback to checkpoint '{checkpoint_id}' initiated.",
        "data": record.data,
    }


@router.get("/rules", response_model=List[RuleSet])
def get_rules() -> List[RuleSet]:
    """Return the currently configured rule sets."""

    return _rule_engine.ruleset


@router.put("/rules", response_model=List[RuleSet])
def update_rules(rules: List[RuleSet]) -> List[RuleSet]:
    """Persist new rules and reload the engine."""

    # Persist the new rules payload
    serialised = [rule.model_dump(mode="json") for rule in rules]
    _RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _RULES_FILE.write_text(json.dumps(serialised, indent=2), encoding="utf-8")

    # Reload the rule engine to reflect the updated rule set
    global _rule_engine
    _rule_engine = RuleEngine(str(_RULES_FILE), safe_mode=_rule_engine.safe_mode)
    return _rule_engine.ruleset
