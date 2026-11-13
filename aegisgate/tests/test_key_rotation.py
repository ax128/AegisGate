"""Console key rotation: in-process proxy token, no /tmp fallback, Fernet guards.

The rotate endpoint used to report success while the gateway kept enforcing the
previous proxy token until restart, and a failed write was redirected to
``/tmp/aegisgate``, which no loader reads. Fernet rotation also continued after
it failed to keep the previous key, and it rewrote the key file even when
``AEGIS_ENCRYPTION_KEY`` would ignore that file.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.core import gateway_keys
from aegisgate.core.gateway_ui_routes import register_ui_routes
from aegisgate.storage import crypto as crypto_mod

_OLD_PROXY_TOKEN = "sk-test-0000-proxy-old"
_FAKE_FERNET_ENV = "fernet-test-key-not-real"
_TMP_PROXY_TOKEN = Path("/tmp/aegisgate/aegis_proxy_token.key")


def _key_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(key_dir))
    monkeypatch.delenv("AEGIS_ENCRYPTION_KEY", raising=False)
    return key_dir


def _client() -> TestClient:
    app = FastAPI()
    register_ui_routes(app)
    return TestClient(app)


def _restore_tmp_proxy_token(before: str | None) -> None:
    if before is None:
        if _TMP_PROXY_TOKEN.exists():
            _TMP_PROXY_TOKEN.unlink()
        parent = _TMP_PROXY_TOKEN.parent
        if parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
        return
    _TMP_PROXY_TOKEN.parent.mkdir(parents=True, exist_ok=True)
    _TMP_PROXY_TOKEN.write_text(before, encoding="utf-8")


def test_proxy_token_rotation_updates_in_process_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful write must be what ``get_proxy_token_value`` returns."""
    key_dir = _key_dir(tmp_path, monkeypatch)
    (key_dir / "aegis_proxy_token.key").write_text(_OLD_PROXY_TOKEN, encoding="utf-8")
    monkeypatch.setattr(gateway_keys, "_proxy_token_value", _OLD_PROXY_TOKEN)

    response = _client().post("/__ui__/api/keys/proxy_token/rotate")

    assert response.status_code == 200
    assert response.json()["rotated"] is True
    stored = (key_dir / "aegis_proxy_token.key").read_text(encoding="utf-8").strip()
    assert stored != _OLD_PROXY_TOKEN
    assert gateway_keys.get_proxy_token_value() == stored


def test_key_write_failure_returns_500_without_tmp_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PermissionError on the real key path must not succeed via ``/tmp``."""
    key_dir = _key_dir(tmp_path, monkeypatch)
    (key_dir / "aegis_proxy_token.key").write_text(_OLD_PROXY_TOKEN, encoding="utf-8")
    monkeypatch.setattr(gateway_keys, "_proxy_token_value", _OLD_PROXY_TOKEN)

    real_named = tempfile.NamedTemporaryFile

    def primary_not_writable(*args: object, **kwargs: object):
        directory = str(kwargs.get("dir") or "")
        if directory.startswith("/tmp/aegisgate"):
            return real_named(*args, **kwargs)
        raise PermissionError("primary key path not writable")

    monkeypatch.setattr(
        "aegisgate.core.gateway_ui_routes.tempfile.NamedTemporaryFile",
        primary_not_writable,
    )
    before_tmp = (
        _TMP_PROXY_TOKEN.read_text(encoding="utf-8") if _TMP_PROXY_TOKEN.is_file() else None
    )
    try:
        response = _client().post("/__ui__/api/keys/proxy_token/rotate")
        body = response.json()
        assert response.status_code == 500, (
            f"status={response.status_code} body={body} "
            f"tmp_exists={_TMP_PROXY_TOKEN.is_file()} "
            f"memory={gateway_keys.get_proxy_token_value()!r}"
        )
        assert body["error"] == "key_write_failed"
        assert gateway_keys.get_proxy_token_value() == _OLD_PROXY_TOKEN
        assert (
            key_dir / "aegis_proxy_token.key"
        ).read_text(encoding="utf-8").strip() == _OLD_PROXY_TOKEN
        if before_tmp is None:
            assert not _TMP_PROXY_TOKEN.exists()
        else:
            assert _TMP_PROXY_TOKEN.read_text(encoding="utf-8") == before_tmp
    finally:
        _restore_tmp_proxy_token(before_tmp)


def test_fernet_rotation_aborts_when_previous_key_cannot_be_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_dir = _key_dir(tmp_path, monkeypatch)
    old_key = Fernet.generate_key().decode("utf-8")
    (key_dir / "aegis_fernet.key").write_text(old_key, encoding="utf-8")
    # write_text on a directory fails; the current key file itself stays writable.
    (key_dir / "aegis_fernet_prev.key").mkdir()
    sentinel = object()
    monkeypatch.setattr(crypto_mod, "_fernet_instance", sentinel)

    response = _client().post("/__ui__/api/keys/fernet/rotate")

    assert response.status_code == 500
    assert response.json()["error"] == "prev_key_save_failed"
    assert (key_dir / "aegis_fernet.key").read_text(encoding="utf-8").strip() == old_key
    assert crypto_mod._fernet_instance is sentinel
    assert (key_dir / "aegis_fernet_prev.key").is_dir()


def test_set_proxy_token_value_publishes_under_the_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rotation's memory update has to take the same lock the getter holds."""
    monkeypatch.setattr(gateway_keys, "_proxy_token_value", _OLD_PROXY_TOKEN)
    entered = False

    class _Lock:
        def __enter__(self) -> "_Lock":
            nonlocal entered
            entered = True
            return self

        def __exit__(self, *args: object) -> bool:
            return False

    monkeypatch.setattr(gateway_keys, "_proxy_token_lock", _Lock())
    gateway_keys.set_proxy_token_value("sk-test-0000-proxy-new")
    assert entered
    assert gateway_keys.get_proxy_token_value() == "sk-test-0000-proxy-new"


def test_fernet_rotation_treats_blank_encryption_key_env_as_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_dir = _key_dir(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", "   ")
    old_key = Fernet.generate_key().decode("utf-8")
    (key_dir / "aegis_fernet.key").write_text(old_key, encoding="utf-8")

    response = _client().post("/__ui__/api/keys/fernet/rotate")

    assert response.status_code == 200
    assert response.json()["rotated"] is True
    stored = (key_dir / "aegis_fernet.key").read_text(encoding="utf-8").strip()
    assert stored != old_key
    assert (key_dir / "aegis_fernet_prev.key").read_text(encoding="utf-8").strip() == old_key


def test_fernet_rotation_refuses_when_encryption_key_env_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_dir = _key_dir(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", _FAKE_FERNET_ENV)
    old_key = Fernet.generate_key().decode("utf-8")
    (key_dir / "aegis_fernet.key").write_text(old_key, encoding="utf-8")
    sentinel = object()
    monkeypatch.setattr(crypto_mod, "_fernet_instance", sentinel)

    response = _client().post("/__ui__/api/keys/fernet/rotate")

    assert response.status_code == 409
    assert response.json()["error"] == "fernet_key_from_env"
    assert (key_dir / "aegis_fernet.key").read_text(encoding="utf-8").strip() == old_key
    assert crypto_mod._fernet_instance is sentinel
    assert not (key_dir / "aegis_fernet_prev.key").exists()
