from __future__ import annotations

from pathlib import Path
from typing import Any
from uxsp.core.identity import Identity, PublicCard

def _normalize_id(entity_id: str | int | PublicCard | Identity) -> str:
    """Ensure entity ID is a non-empty string."""
    if isinstance(entity_id, (PublicCard, Identity)):
        return entity_id.entity_id
    norm = str(entity_id).strip()
    if not norm:
        raise ValueError("Entity ID cannot be empty.")
    return norm


def _safe_is_file(path_val: Any) -> bool:
    """Safely check if path_val is an existing file without raising OSError on long strings."""
    if not isinstance(path_val, (str, Path)):
        return False
    try:
        p = Path(path_val)
        return p.is_file()
    except (OSError, ValueError):
        return False
