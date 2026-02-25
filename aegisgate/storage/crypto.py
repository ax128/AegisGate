"""Lightweight reversible encoding wrapper.

Replace with strong encryption in production (e.g. Fernet/KMS).
"""

from __future__ import annotations

import base64
import json


def encrypt_mapping(mapping: dict[str, str]) -> str:
    raw = json.dumps(mapping, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("utf-8")


def decrypt_mapping(payload: str) -> dict[str, str]:
    raw = base64.b64decode(payload.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))
