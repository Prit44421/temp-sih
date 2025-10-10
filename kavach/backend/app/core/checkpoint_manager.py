"""Encrypted checkpoint storage for Kavach rule executions."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken


logger = logging.getLogger(__name__)

DEFAULT_BASE_DIR = Path.home() / ".kavach"


def _normalise_rule_id(rule_id: str) -> str:
    """Return a filesystem-safe representation of ``rule_id``."""

    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in rule_id)


def _load_or_create_key(path: Path) -> bytes:
    """Load an encryption key from ``path`` or create one if missing."""

    if path.exists():
        key = path.read_bytes()
        logger.debug("Loaded existing checkpoint key from %s", path)
        return key

    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    path.write_bytes(key)
    logger.info("Generated new checkpoint encryption key at %s", path)
    return key


@dataclass(frozen=True)
class CheckpointRecord:
    """Structured representation of a checkpoint."""

    id: str
    rule_id: str
    timestamp: datetime
    data: Dict[str, Any]


class CheckpointManager:
    """Create, decrypt, list, and delete encrypted checkpoints."""

    def __init__(self, base_dir: Path | None = None, *, encryption_key: bytes | None = None) -> None:
        self._base_dir = base_dir or DEFAULT_BASE_DIR
        self._checkpoint_dir = self._base_dir / "checkpoints"
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)

        key_path = self._base_dir / "session.key"
        key = encryption_key or _load_or_create_key(key_path)
        self._cipher = Fernet(key)

    # ------------------------------------------------------------------
    # Public API
    def create_checkpoint(self, rule_id: str, data: Dict[str, Any]) -> str:
        """Persist a new checkpoint and return its identifier."""

        safe_rule_id = _normalise_rule_id(rule_id)
        timestamp = datetime.now(tz=timezone.utc)
        checkpoint_id = f"{timestamp.strftime('%Y%m%dT%H%M%SZ')}-{safe_rule_id}"
        record = {
            "id": checkpoint_id,
            "rule_id": rule_id,
            "timestamp": timestamp.isoformat(),
            "data": data,
        }

        payload = json.dumps(record, separators=(",", ":")).encode("utf-8")
        encrypted = self._cipher.encrypt(payload)
        self._checkpoint_path(checkpoint_id).write_bytes(encrypted)

        logger.info("Created checkpoint %s for rule %s", checkpoint_id, rule_id)
        return checkpoint_id

    def restore_checkpoint(self, checkpoint_id: str) -> Optional[CheckpointRecord]:
        """Return the checkpoint data for ``checkpoint_id`` if available."""

        path = self._checkpoint_path(checkpoint_id)
        if not path.exists():
            logger.warning("Checkpoint %s not found", checkpoint_id)
            return None

        try:
            decrypted = self._cipher.decrypt(path.read_bytes())
            payload = json.loads(decrypted.decode("utf-8"))
            timestamp = datetime.fromisoformat(payload["timestamp"])
            record = CheckpointRecord(
                id=payload["id"],
                rule_id=payload["rule_id"],
                timestamp=timestamp,
                data=payload["data"],
            )
            logger.info("Loaded checkpoint %s", checkpoint_id)
            return record
        except InvalidToken:
            logger.error(
                "Failed to decrypt checkpoint %s; the encryption key may be incorrect or the file is corrupt",
                checkpoint_id,
            )
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            logger.exception("Malformed checkpoint %s: %s", checkpoint_id, exc)

        return None

    def list_checkpoints(self) -> List[str]:
        """Return the identifiers of all stored checkpoints sorted by timestamp."""

        ids = [p.stem for p in self._checkpoint_dir.glob("*.kcp") if p.is_file()]
        return sorted(ids)

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """Remove ``checkpoint_id`` from disk. Returns ``True`` when deleted."""

        path = self._checkpoint_path(checkpoint_id)
        if path.exists():
            path.unlink()
            logger.info("Deleted checkpoint %s", checkpoint_id)
            return True

        logger.debug("Attempted to delete nonexistent checkpoint %s", checkpoint_id)
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    def _checkpoint_path(self, checkpoint_id: str) -> Path:
        return self._checkpoint_dir / f"{checkpoint_id}.kcp"


__all__ = ["CheckpointManager", "CheckpointRecord"]

if __name__ == '__main__':
    manager = CheckpointManager()

    # 1. Create a checkpoint
    print("--- Creating Checkpoint ---")
    mock_data_to_save = {"file": "/etc/sysctl.conf", "previous_content": "net.ipv6.conf.all.disable_ipv6=0"}
    chk_id = manager.create_checkpoint("ubuntu.network.disable-ipv6", mock_data_to_save)

    # 2. List checkpoints
    print("\n--- Listing Checkpoints ---")
    checkpoints = manager.list_checkpoints()
    print(f"Available checkpoints: {checkpoints}")
    assert chk_id in checkpoints

    # 3. Restore a checkpoint
    print("\n--- Restoring Checkpoint ---")
    restored_data = manager.restore_checkpoint(chk_id)
    assert restored_data is not None
    assert restored_data['data'] == mock_data_to_save

    # 4. Test restoring a non-existent checkpoint
    print("\n--- Testing Non-Existent Checkpoint ---")
    manager.restore_checkpoint("non-existent-id")
