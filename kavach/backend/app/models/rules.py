"""
Pydantic Models for Rule Validation
"""
from typing import List, Dict, Any, Literal
from pydantic import BaseModel, Field

class RuleAction(BaseModel):
    """Defines an action within a rule (check, remediate, validate)."""
    type: Literal["shell", "powershell", "python"]
    cmd: str
    expect: str | None = None

class RollbackAction(BaseModel):
    """Defines a rollback action."""
    type: Literal["restore_checkpoint"]

class Rule(BaseModel):
    """Defines a single hardening rule."""
    id: str
    title: str
    description: str
    level: Literal["basic", "moderate", "strict"]
    platforms: List[str]
    check: RuleAction
    remediate: RuleAction
    validate: RuleAction
    rollback: RollbackAction

class RuleSet(BaseModel):
    """Defines a set of rules for a specific OS and module."""
    os: str
    module: str
    rules: List[Rule]
