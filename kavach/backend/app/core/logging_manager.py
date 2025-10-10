"""Structured logging management for Kavach operations."""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel


class LogEntry(BaseModel):
    """Structured log entry for Kavach operations."""
    
    timestamp: str
    level: str
    rule_id: Optional[str] = None
    action: Optional[str] = None  # check, remediate, validate, rollback
    prev_state: Optional[str] = None
    new_state: Optional[str] = None
    status: str  # success, failure, skipped, error
    cmd: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    user: Optional[str] = None
    session_id: str
    message: str


class LoggingManager:
    """Centralized logging manager with structured JSON logging and rotation."""
    
    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or Path.home() / ".kavach" / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.session_id = str(uuid.uuid4())
        self.user = os.getenv("USERNAME") or os.getenv("USER") or "unknown"
        
        # Set up structured JSON logger
        self.structured_logger = self._setup_structured_logger()
        
        # Set up standard application logger
        self.app_logger = self._setup_app_logger()
        
    def _setup_structured_logger(self) -> logging.Logger:
        """Set up JSON structured logger with rotation."""
        logger = logging.getLogger("kavach.structured")
        logger.setLevel(logging.INFO)
        
        # Clear any existing handlers to avoid duplicates
        logger.handlers.clear()
        
        # JSON log file with rotation
        json_log_file = self.log_dir / "kavach-operations.jsonl"
        json_handler = logging.handlers.RotatingFileHandler(
            json_log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8"
        )
        json_handler.setLevel(logging.INFO)
        
        # Custom formatter for JSON output
        json_formatter = JsonFormatter()
        json_handler.setFormatter(json_formatter)
        
        logger.addHandler(json_handler)
        logger.propagate = False  # Don't propagate to root logger
        
        return logger
    
    def _setup_app_logger(self) -> logging.Logger:
        """Set up application logger with standard formatting."""
        logger = logging.getLogger("kavach.app")
        logger.setLevel(logging.INFO)
        
        # Clear any existing handlers
        logger.handlers.clear()
        
        # Application log file with rotation
        app_log_file = self.log_dir / "kavach-app.log"
        app_handler = logging.handlers.RotatingFileHandler(
            app_log_file,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
            encoding="utf-8"
        )
        app_handler.setLevel(logging.INFO)
        
        # Standard formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        app_handler.setFormatter(formatter)
        
        logger.addHandler(app_handler)
        logger.propagate = False
        
        return logger
    
    def log_rule_event(
        self,
        level: str,
        rule_id: Optional[str] = None,
        action: Optional[str] = None,
        prev_state: Optional[str] = None,
        new_state: Optional[str] = None,
        status: str = "info",
        cmd: Optional[str] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        message: str = "",
        **kwargs: Any
    ) -> None:
        """Log a structured rule execution event."""
        
        entry = LogEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            level=level,
            rule_id=rule_id,
            action=action,
            prev_state=prev_state,
            new_state=new_state,
            status=status,
            cmd=cmd,
            stdout=stdout,
            stderr=stderr,
            user=self.user,
            session_id=self.session_id,
            message=message
        )
        
        # Log to structured logger
        log_data = entry.model_dump(exclude_none=True)
        log_data.update(kwargs)  # Add any extra fields
        
        self.structured_logger.info("", extra={"structured_data": log_data})
    
    def log_app_event(self, level: str, message: str, **kwargs: Any) -> None:
        """Log an application event to the standard logger."""
        log_level = getattr(logging, level.upper(), logging.INFO)
        self.app_logger.log(log_level, message, extra=kwargs)
    
    def log_checkpoint_created(self, checkpoint_id: str, rule_id: str) -> None:
        """Log checkpoint creation event."""
        self.log_rule_event(
            level="INFO",
            rule_id=rule_id,
            action="checkpoint",
            status="success",
            message=f"Checkpoint {checkpoint_id} created for rule {rule_id}"
        )
    
    def log_rule_check(self, rule_id: str, cmd: str, stdout: str, stderr: str, exit_code: int) -> None:
        """Log rule check execution."""
        status = "success" if exit_code == 0 else "failure"
        self.log_rule_event(
            level="INFO",
            rule_id=rule_id,
            action="check",
            prev_state=stdout.strip()[:200] if stdout else None,
            status=status,
            cmd=cmd,
            stdout=stdout if stdout else None,
            stderr=stderr if stderr else None,
            message=f"Rule check for {rule_id} completed with exit code {exit_code}"
        )
    
    def log_rule_remediate(self, rule_id: str, cmd: str, stdout: str, stderr: str, exit_code: int) -> None:
        """Log rule remediation execution."""
        status = "success" if exit_code == 0 else "failure"
        self.log_rule_event(
            level="INFO",
            rule_id=rule_id,
            action="remediate",
            new_state=stdout.strip()[:200] if stdout else None,
            status=status,
            cmd=cmd,
            stdout=stdout if stdout else None,
            stderr=stderr if stderr else None,
            message=f"Rule remediation for {rule_id} completed with exit code {exit_code}"
        )
    
    def log_rule_validate(self, rule_id: str, cmd: str, stdout: str, stderr: str, exit_code: int, expected: str) -> None:
        """Log rule validation execution."""
        actual = stdout.strip()
        validation_passed = exit_code == 0 and (not expected or actual == expected)
        status = "success" if validation_passed else "failure"
        
        self.log_rule_event(
            level="INFO",
            rule_id=rule_id,
            action="validate",
            prev_state=expected,
            new_state=actual[:200] if actual else None,
            status=status,
            cmd=cmd,
            stdout=stdout if stdout else None,
            stderr=stderr if stderr else None,
            message=f"Rule validation for {rule_id} {'passed' if validation_passed else 'failed'}"
        )
    
    def log_rollback_attempt(self, checkpoint_id: str, rule_id: str, success: bool) -> None:
        """Log rollback attempt."""
        status = "success" if success else "failure"
        self.log_rule_event(
            level="INFO",
            rule_id=rule_id,
            action="rollback",
            status=status,
            message=f"Rollback to checkpoint {checkpoint_id} for rule {rule_id} {'succeeded' if success else 'failed'}"
        )
    
    def log_compliance_check(self, rule_id: str, is_compliant: bool, message: str = "") -> None:
        """Log compliance check result."""
        status = "compliant" if is_compliant else "non_compliant"
        self.log_rule_event(
            level="INFO",
            rule_id=rule_id,
            action="compliance_check",
            status=status,
            message=message or f"Rule {rule_id} is {'compliant' if is_compliant else 'not compliant'}"
        )
    
    def get_session_logs(self) -> list[Dict[str, Any]]:
        """Retrieve all logs for the current session."""
        logs = []
        json_log_file = self.log_dir / "kavach-operations.jsonl"
        
        if not json_log_file.exists():
            return logs
        
        try:
            with open(json_log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        if log_entry.get('session_id') == self.session_id:
                            logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue
        except IOError:
            pass
        
        return logs
    
    def get_rule_history(self, rule_id: str, limit: int = 50) -> list[Dict[str, Any]]:
        """Get execution history for a specific rule."""
        logs = []
        json_log_file = self.log_dir / "kavach-operations.jsonl"
        
        if not json_log_file.exists():
            return logs
        
        try:
            with open(json_log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        if log_entry.get('rule_id') == rule_id:
                            logs.append(log_entry)
                            if len(logs) >= limit:
                                break
                    except json.JSONDecodeError:
                        continue
        except IOError:
            pass
        
        return logs[-limit:]  # Return most recent entries


class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        if hasattr(record, 'structured_data'):
            return json.dumps(record.structured_data, ensure_ascii=False)
        
        # Fallback for non-structured log records
        return json.dumps({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name
        }, ensure_ascii=False)


# Global logging manager instance
_logging_manager: Optional[LoggingManager] = None


def get_logging_manager() -> LoggingManager:
    """Get the global logging manager instance."""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager


def setup_logging(log_dir: Optional[Path] = None) -> LoggingManager:
    """Set up the global logging manager."""
    global _logging_manager
    _logging_manager = LoggingManager(log_dir)
    return _logging_manager


__all__ = ["LoggingManager", "LogEntry", "get_logging_manager", "setup_logging"]