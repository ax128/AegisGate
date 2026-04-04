"""Secure helpers for creating/writing local files.

These helpers enforce least-privilege defaults for runtime data files such as
audit logs and sample captures.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TextIO


def open_append_0600(path: Path, *, encoding: str = "utf-8") -> TextIO:
    """Open a file for appending, ensuring permissions are 0600 when possible.

    - Creates parent directories if needed.
    - Creates the file with mode 0600 (subject to umask), and attempts to chmod
      to 0600 for existing files.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    fd = os.open(str(path), flags, 0o600)
    try:
        handle = os.fdopen(fd, "a", encoding=encoding)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return handle

