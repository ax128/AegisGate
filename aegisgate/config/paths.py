"""Single resolver for the runtime config directory.

Three call sites used to answer "where is ``config/``?" independently.
``storage/crypto`` and ``config/redact_values`` honoured ``AEGIS_CONFIG_DIR``;
the console's key-management page resolved ``<cwd>/config`` unconditionally.
Under an ``AEGIS_CONFIG_DIR`` layout that divergence made key rotation write the
new Fernet key where ``crypto`` never reads it — the console reported success
and the old key stayed in force. ``test_ui_key_rotate_honours_aegis_config_dir``
pinned that as a strict xfail; this module is the fix.

``init_config`` deliberately keeps its own resolver: it falls back to the
directory holding ``security_rules_path`` so a bootstrap can find the rules tree
even when cwd is somewhere else. That is a different question from "where do
runtime secrets live", so the two are not collapsed here.
"""

from __future__ import annotations

import os
from pathlib import Path


def config_dir() -> Path:
    """Directory holding runtime config files (keys, exact-value store, ``.env``).

    ``AEGIS_CONFIG_DIR`` wins when set, otherwise ``<cwd>/config``. A relative
    ``AEGIS_CONFIG_DIR`` still resolves against cwd, which is why a caller that
    memoises this must key the cache on both the env var and cwd.
    """
    env = os.environ.get("AEGIS_CONFIG_DIR", "").strip()
    if env:
        return Path(env).resolve()
    return (Path.cwd() / "config").resolve()
