"""Serialized, verified writes to ``security_filters.yaml``.

Every console write to the rules file used to be an unguarded
read-modify-write: load the whole document, change part of it, write it back.
``If-Match`` was checked before the read that produced the bytes actually
written, three different code paths wrote the same file with no mutual
exclusion, and the reload that follows the write reported nothing at all. The
failure that combination produces is not a lost edit — it is a security policy
that reports "saved" while the gateway keeps enforcing something else.

This module is the single door. One process-wide lock **per rules file, shared
by every section**, so a redaction write and an injection_detector write cannot
interleave. Inside that lock: read the bytes, derive the ETag from *those*
bytes, validate ``If-Match`` against it, patch the text with comments intact,
re-parse and prove nothing outside the target section moved, compile what each
redaction layer would compile, probe changed regexes against fixed adversarial
samples, take a millisecond-stamped backup, replace atomically, reload, and
verify that what is on disk and in memory is what was intended.

If that last verification fails the file is rolled back — but only after
**comparing** what is on disk with what this transaction wrote. An
unconditional restore would hand a concurrent writer's committed change straight
back to the previous bytes; when the comparison shows someone else already
landed, the write reports ``concurrent_write_detected`` and leaves the file
alone.
"""

from __future__ import annotations

import copy
import os
import re
import stat
import tempfile
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from aegisgate.config.security_rules import resolve_rules_file
from aegisgate.core.audit import write_audit
from aegisgate.core.regex_probe import MAX_REGEX_LEN, probe
from aegisgate.core.ui_etag import ABSENT_ETAG, etag_for_bytes
from aegisgate.util.logger import logger

# Backups are named ``<file>.bak-<timestamp>`` and never ``<file>.bak-<ts>.yaml``:
# ``hot_reload.build_watcher`` watches ``policies_dir.glob("*.yaml")``, so the
# second form would register every backup as a live policy file.
_BACKUP_INFIX = ".bak-"
_MAX_BACKUPS = 20

# Fixed inputs every changed regex is matched against before it is allowed onto
# disk. They exist because the console's own tester lets the caller pick the
# samples: a rule author testing ``(a+)+$`` with "hello" sees a clean pass. These
# are the shapes that make a backtracking pattern show itself.
_ADVERSARIAL_PROBE_SAMPLES: tuple[str, ...] = (
    "a" * 1500,
    "a" * 600 + "!",
    "ab" * 600,
    "0" * 1200,
    " " * 900 + "x",
    "api_key=" + "A" * 900,
    "Authorization: Bearer " + "x" * 900,
    "<" * 500 + ">" * 500,
    "/" * 600 + "?" + "=" * 300,
    "-" * 700 + "@" + "." * 300,
    "\t" * 600 + "end",
    ("A" * 120 + "@") * 8,
)

_KEY_LINE = re.compile(r"^([^\s#][^:]*):")


class RulesWriteError(Exception):
    """A rules write that must be reported to the caller, not swallowed."""

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        status: int = 422,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status
        self.extra = extra or {}

    def as_payload(self) -> dict[str, Any]:
        return {"error": self.code, "detail": self.detail, **self.extra}


@dataclass
class RulesSnapshot:
    """The rules file as it was read under the lock."""

    path: Path
    exists: bool
    text: str
    data: dict[str, Any]
    etag: str


@dataclass
class RulesChange:
    """What a caller wants the file to become."""

    expected: dict[str, Any]
    # Patched text with comments preserved. ``None`` is only acceptable when the
    # file does not exist yet: there is nothing to preserve, so it is dumped.
    text: str | None = None
    changed_top_keys: tuple[str, ...] = ()
    audit: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# The per-file lock, shared by every section
# ---------------------------------------------------------------------------

_FILE_LOCKS: dict[str, threading.RLock] = {}
_FILE_LOCKS_GUARD = threading.Lock()


def rules_file_lock(path: Path) -> threading.RLock:
    """The one lock guarding *path*, created on first use."""
    key = str(path)
    with _FILE_LOCKS_GUARD:
        lock = _FILE_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _FILE_LOCKS[key] = lock
        return lock


# ---------------------------------------------------------------------------
# Structural verification
# ---------------------------------------------------------------------------


def _comment_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip().startswith("#")]


def top_level_blocks(text: str) -> dict[str, str]:
    """The document split by top-level key, prologue under ``""``.

    Lines between two top-level keys are attributed to the earlier one, so a
    comment moving between sections still registers as a change.
    """
    blocks: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.splitlines():
        match = _KEY_LINE.match(line)
        if match and not line[:1].isspace():
            current = match.group(1).strip()
            blocks.setdefault(current, [])
        blocks[current].append(line)
    return {key: "\n".join(lines) for key, lines in blocks.items()}


def _verify_patch(snapshot: RulesSnapshot, change: RulesChange, after_text: str) -> None:
    try:
        parsed = yaml.safe_load(after_text)
    except yaml.YAMLError as exc:
        raise RulesWriteError(
            "rules_patch_invalid_yaml",
            f"补丁后的规则文件无法解析：{exc}",
        ) from exc
    if not isinstance(parsed, dict):
        raise RulesWriteError("rules_patch_invalid_yaml", "补丁后的规则文件不是映射结构")
    if parsed != change.expected:
        raise RulesWriteError(
            "rules_patch_mismatch",
            "补丁结果与预期结构不一致，已放弃写入（文件未改动）",
        )
    if not snapshot.exists:
        return

    if _comment_lines(after_text) != _comment_lines(snapshot.text):
        raise RulesWriteError(
            "rules_patch_comment_loss",
            "补丁会丢失规则文件中的注释，已放弃写入（文件未改动）",
        )

    before_blocks = top_level_blocks(snapshot.text)
    after_blocks = top_level_blocks(after_text)
    allowed = set(change.changed_top_keys)
    for key in set(before_blocks) | set(after_blocks):
        if key in allowed:
            continue
        if before_blocks.get(key) != after_blocks.get(key):
            raise RulesWriteError(
                "rules_patch_collateral_change",
                f"补丁改动了本次目标之外的配置段 '{key or '文件头'}'，已放弃写入（文件未改动）",
            )


# ---------------------------------------------------------------------------
# Candidate compilation: what each layer would build from the new document
# ---------------------------------------------------------------------------

_FIELD_FALLBACK_TEMPLATES: tuple[tuple[str, str], ...] = (
    (
        "FIELD_SECRET",
        r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token"
        r"|password|passwd|client[_-]?secret|private[_-]?key|secret(?:_key)?)\b\s*[:=]\s*"
        r"(?:bearer\s+)?[A-Za-z0-9._~+/=-]{{{min_len},}}",
    ),
    (
        "AUTH_BEARER",
        r"(?i)\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{{{min_len},}}",
    ),
)


def _field_min_len(rules: dict[str, Any], floor: int) -> int:
    raw = rules.get("field_value_min_len", 12)
    try:
        return max(floor, int(raw))
    except (TypeError, ValueError) as exc:
        raise RulesWriteError(
            "invalid_field_value_min_len",
            f"redaction.field_value_min_len 必须是整数（当前 {raw!r}）",
            status=400,
        ) from exc


def _fallback_field_patterns(min_len: int, *, lowercase: bool) -> list[tuple[str, str]]:
    return [
        (pattern_id.lower() if lowercase else pattern_id, template.format(min_len=min_len))
        for pattern_id, template in _FIELD_FALLBACK_TEMPLATES
    ]


# Each layer reads the same YAML differently, and the pre-write compile is worth
# nothing unless it models that faithfully: the ids are cased differently, the
# ``field_value_min_len`` floors differ, the legacy bare-string form gets a
# positional id in two layers and a fixed one in the third, and V2 compiles its
# two code fallbacks *in addition to* an explicit list where V1 uses them only
# when the list is empty.
@dataclass(frozen=True)
class _LayerSpec:
    """One redaction layer's reading of ``redaction.*``."""

    name: str
    field_floor: int
    # V2 compiles pii and field entries through one shared loop that lowercases
    # ids, defaults a missing id to ``rule`` and skips a non-string regex.
    lowercase: bool
    field_default_positional: bool
    always_fallback: bool


_LAYER_SPECS: tuple[_LayerSpec, ...] = (
    # filters/redaction.py
    _LayerSpec("v1_pipeline", 8, False, False, False),
    # adapters/openai_compat/sanitize.py
    _LayerSpec("v1_forward", 8, False, True, False),
    # adapters/v2_proxy/router.py
    _LayerSpec("v2_request", 12, True, True, True),
)


def malformed_pii_entries(data: Any) -> list[str]:
    """Non-mapping ``redaction.pii_patterns`` entries, rendered for reporting."""
    rules = data.get("redaction") if isinstance(data, dict) else None
    if not isinstance(rules, dict):
        return []
    return [
        str(item)
        for item in rules.get("pii_patterns") or []
        if not isinstance(item, dict)
    ]


def _pii_entries(rules: dict[str, Any], spec: _LayerSpec) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for item in rules.get("pii_patterns") or []:
        if not isinstance(item, dict):
            # Every layer skips a non-mapping entry. Refusing an unrelated edit
            # because one is already in the file would only leave the console
            # unable to fix it; ``malformed_pii_entries`` is what reports them,
            # and a write that *introduces* one is still refused.
            continue
        regex = item.get("regex")
        if spec.lowercase:
            if not isinstance(regex, str) or not regex.strip():
                continue
            pattern_id = str(item.get("id") or "RULE").strip().lower() or "rule"
        else:
            if not regex:
                continue
            pattern_id = str(item.get("id", "PII")).upper()
        entries.append((pattern_id, str(regex)))
    return entries


def _field_entries(rules: dict[str, Any], spec: _LayerSpec) -> list[tuple[str, str]]:
    items = rules.get("field_value_patterns") or []
    fallback = _fallback_field_patterns(
        _field_min_len(rules, spec.field_floor), lowercase=spec.lowercase
    )
    if not items:
        return fallback
    # V1 treats the code fallback as the *alternative* to an explicit list; V2
    # compiles it either way, which is why its two fallback ids are always live.
    entries: list[tuple[str, str]] = list(fallback) if spec.always_fallback else []
    for index, item in enumerate(items, start=1):
        positional_default = (
            f"FIELD_SECRET_{index}" if spec.field_default_positional else "FIELD_SECRET"
        )
        if isinstance(item, dict):
            regex = item.get("regex")
            if spec.lowercase:
                if not isinstance(regex, str) or not regex.strip():
                    continue
                pattern_id = str(item.get("id") or "RULE").strip().lower() or "rule"
            else:
                if not regex:
                    continue
                pattern_id = str(item.get("id", positional_default)).upper()
        elif isinstance(item, str) or not spec.lowercase:
            # The V1 layers hand any non-mapping entry straight to re.compile;
            # V2 recognises only the bare-string form.
            regex = item
            if not regex:
                continue
            pattern_id = f"field_secret_{index}" if spec.lowercase else positional_default
        else:
            continue
        entries.append((pattern_id, str(regex)))
    return entries


def compile_redaction_layers(
    data: dict[str, Any],
) -> tuple[dict[str, tuple[tuple[str, str], ...]], list[tuple[str, str, str]]]:
    """Compile the redaction patterns of all three layers from *data*.

    Returns ``(signature, failures)``: the per-layer id/pattern pairs that
    compiled, and the ones that did not. Layers mirror the live call sites —
    ``filters/redaction.py`` (V1 pipeline), ``openai_compat/sanitize.py`` (V1
    forward) and ``v2_proxy/router.py`` (V2) — including their differing default
    ids, ``field_value_min_len`` floors and fallback rules (see ``_LAYER_SPECS``).
    """
    rules = data.get("redaction") if isinstance(data, dict) else None
    if rules is None:
        rules = {}
    if not isinstance(rules, dict):
        raise RulesWriteError("invalid_redaction_section", "redaction 配置段必须是映射", status=400)

    signature: dict[str, tuple[tuple[str, str], ...]] = {}
    failures: list[tuple[str, str, str]] = []
    for spec in _LAYER_SPECS:
        compiled: list[tuple[str, str]] = []
        for pattern_id, regex in (*_pii_entries(rules, spec), *_field_entries(rules, spec)):
            try:
                re.compile(regex)
            except re.error as exc:
                failures.append((spec.name, regex, str(exc)))
                continue
            compiled.append((pattern_id, regex))
        signature[spec.name] = tuple(compiled)
    return signature, failures


# ---------------------------------------------------------------------------
# Regex inventory: which patterns this write actually introduces or changes
# ---------------------------------------------------------------------------


def regex_inventory(data: Any) -> dict[str, str]:
    """Every rule regex in the document, keyed by section path and rule id."""
    found: dict[str, str] = {}

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}" if path else str(key))
            return
        if not isinstance(node, list):
            return
        for index, item in enumerate(node, start=1):
            if isinstance(item, dict):
                regex = item.get("regex")
                if isinstance(regex, str):
                    found[f"{path}[{item.get('id') or index}]"] = regex
                else:
                    walk(item, f"{path}[{index}]")
            elif isinstance(item, str) and path.endswith("_patterns"):
                # The legacy bare-string form several pattern lists still accept.
                found[f"{path}[{index}]"] = item

    walk(data, "")
    return found


def changed_regexes(before: dict[str, Any], after: dict[str, Any]) -> list[tuple[str, str]]:
    """Regexes *after* introduces or rewrites relative to *before*."""
    old = regex_inventory(before)
    return [(key, value) for key, value in regex_inventory(after).items() if old.get(key) != value]


def _reject_uncompilable(failures: list[tuple[str, str, str]], changed: list[tuple[str, str]]) -> None:
    """Fail the write when a *new or changed* regex will not compile.

    Patterns already on disk that do not compile are left alone: every layer
    already skips them with a warning, and blocking an unrelated edit until an
    old rule is fixed would be its own outage.
    """
    incoming = {regex for _, regex in changed}
    for layer, regex, error in failures:
        if regex in incoming:
            raise RulesWriteError(
                "invalid_regex",
                f"正则在 {layer} 层无法编译：{error}",
                status=400,
            )


def _reject_new_malformed_entries(before: dict[str, Any], after: dict[str, Any]) -> None:
    """Refuse a write that *introduces* a non-mapping ``pii_patterns`` entry.

    One that is already in the file is reported by the panel and skipped by
    every layer, so failing every write to the whole file over it would only
    lock the console out of fixing it — including out of removing the entry.
    Comparison is by value rather than by position, so inserting a rule above an
    existing malformed entry does not read as introducing one.
    """
    existing = Counter(malformed_pii_entries(before))
    introduced = sorted((Counter(malformed_pii_entries(after)) - existing).elements())
    if introduced:
        raise RulesWriteError(
            "invalid_pii_pattern_entry",
            "redaction.pii_patterns 的每一项都必须是映射（含 id 与 regex）：" + "、".join(introduced),
            status=400,
        )


def _probe_changed_regexes(changed: list[tuple[str, str]]) -> None:
    for key, regex in changed:
        if len(regex) > MAX_REGEX_LEN:
            raise RulesWriteError(
                "regex_too_long",
                f"规则 {key} 的正则超过 {MAX_REGEX_LEN} 字符",
                status=400,
            )
        outcome = probe(regex, list(_ADVERSARIAL_PROBE_SAMPLES))
        if outcome.get("error"):
            raise RulesWriteError(
                "invalid_regex",
                f"规则 {key} 的正则无法编译：{outcome['error']}",
                status=400,
            )
        if outcome.get("timed_out"):
            raise RulesWriteError(
                "regex_probe_timeout",
                (
                    f"规则 {key} 的正则在服务端固定对抗样本上 "
                    f"{outcome['timeout_seconds']} 秒内未跑完，极可能存在灾难性回溯，已拒绝保存"
                ),
                status=400,
            )


# ---------------------------------------------------------------------------
# Backups and atomic replacement
# ---------------------------------------------------------------------------


def _file_mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def _atomic_write(path: Path, payload: bytes, mode: int | None) -> None:
    with tempfile.NamedTemporaryFile(
        "wb", delete=False, dir=str(path.parent), suffix=".tmp"
    ) as tmp:
        tmp.write(payload)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    if mode is not None:
        os.chmod(tmp_path, mode)
    tmp_path.replace(path)


def _backup_stamp() -> str:
    # Millisecond precision, because two console saves a few hundred
    # milliseconds apart used to produce the same name and the second one
    # overwrote the only copy of the state before the first.
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y%m%dT%H%M%S") + f".{now.microsecond // 1000:03d}Z"


def create_backup(path: Path, payload: bytes, mode: int | None) -> Path:
    stamp = _backup_stamp()
    candidate = path.with_name(f"{path.name}{_BACKUP_INFIX}{stamp}")
    serial = 0
    while candidate.exists():
        serial += 1
        candidate = path.with_name(f"{path.name}{_BACKUP_INFIX}{stamp}-{serial}")
    candidate.write_bytes(payload)
    if mode is not None:
        os.chmod(candidate, mode)
    _prune_backups(path)
    return candidate


def _prune_backups(path: Path) -> None:
    backups = sorted(path.parent.glob(f"{path.name}{_BACKUP_INFIX}*"))
    for stale in backups[:-_MAX_BACKUPS]:
        try:
            stale.unlink()
        except OSError as exc:  # pragma: no cover - best effort housekeeping
            logger.warning("rules backup prune failed path=%s error=%s", stale, exc)


# ---------------------------------------------------------------------------
# The transaction
# ---------------------------------------------------------------------------


def _check_if_match(if_match: str | None, current_etag: str, require: bool) -> None:
    from aegisgate.core.ui_etag import if_match_is_stale, if_match_is_specific

    if require and not if_match_is_specific(if_match):
        raise RulesWriteError(
            "if_match_required",
            "该接口要求携带具体的 If-Match，不接受缺失或 '*'",
            status=428,
            extra={"current_etag": current_etag},
        )
    if if_match_is_stale(if_match, current_etag):
        raise RulesWriteError(
            "etag_mismatch",
            "该配置已被其他会话修改，请刷新后重新提交，避免覆盖对方的改动",
            status=409,
            extra={"current_etag": current_etag},
        )


def _compare_and_restore(
    path: Path, after_bytes: bytes, before_bytes: bytes, existed: bool, mode: int | None
) -> str:
    """Restore the pre-write bytes, but only if this write is still the one on disk."""
    try:
        current = path.read_bytes() if path.is_file() else None
    except OSError:
        current = None
    if current != after_bytes:
        return "not_restored_concurrent_write"
    if existed:
        _atomic_write(path, before_bytes, mode)
    else:
        try:
            path.unlink()
        except OSError:  # pragma: no cover - best effort
            return "not_restored_concurrent_write"
    _reload_rules()
    return "restored"


def _reload_rules() -> dict[str, Any]:
    from aegisgate.core.hot_reload import reload_security_rules

    result = reload_security_rules()
    return result if isinstance(result, dict) else {"ok": True, "layers": {}, "errors": []}


def _loader_problem(expected: dict[str, Any]) -> str | None:
    """``None`` when the rules loader is serving the document just written.

    The old check here recompiled the bytes this transaction had produced and
    compared them with the candidate compiled from the same bytes, so it could
    never fail. What actually goes wrong after a write is that a *cache* keeps
    serving the previous document — the loader is mtime-keyed and every layer
    rebuilds from it — and that is what this asks about.
    """
    from aegisgate.config.security_rules import load_security_rules

    wanted = expected.get("redaction")
    if not isinstance(wanted, dict):
        return None
    try:
        live = load_security_rules().get("redaction", {})
    except Exception as exc:  # noqa: BLE001 - any loader failure is a failed write
        return f"loader_failed:{type(exc).__name__}"
    if not isinstance(live, dict):
        return "loader_failed:not_a_mapping"
    for key, value in wanted.items():
        # Keys the file omits are filled in from the built-in defaults and a
        # nested mapping is deep-merged rather than replaced, so only the keys
        # this document actually spells out can be compared.
        if isinstance(value, dict):
            continue
        if live.get(key) != value:
            return f"loader_stale:{key}"
    return None


def _verify_applied(
    path: Path,
    after_bytes: bytes,
    signature: dict[str, tuple[tuple[str, str], ...]],
    reload_result: dict[str, Any],
    expected: dict[str, Any],
) -> list[str]:
    problems: list[str] = []
    disk_bytes: bytes | None = None
    try:
        disk_bytes = path.read_bytes()
    except OSError as exc:
        problems.append(f"disk_unreadable:{type(exc).__name__}")
    if disk_bytes is not None:
        if disk_bytes != after_bytes:
            problems.append("disk_bytes_mismatch")
        try:
            disk_signature, _ = compile_redaction_layers(
                yaml.safe_load(disk_bytes.decode("utf-8")) or {}
            )
            if disk_signature != signature:
                problems.append("compiled_patterns_mismatch")
        except (RulesWriteError, yaml.YAMLError, UnicodeDecodeError):
            problems.append("recompile_failed")
    stale = _loader_problem(expected)
    if stale:
        problems.append(stale)
    if not reload_result.get("ok", True):
        failed = [
            layer
            for layer, state in (reload_result.get("layers") or {}).items()
            if state != "ok"
        ]
        problems.append("hot_reload_failed:" + ",".join(sorted(failed)))
    return problems


def write_rules_file(
    build: Callable[[RulesSnapshot], RulesChange],
    *,
    if_match: str | None,
    event: str,
    actor: str = "unknown",
    require_if_match: bool = False,
    rules_path: Path | None = None,
) -> dict[str, Any]:
    """Run one verified, audited write against the rules file.

    *build* receives the snapshot read under the lock and returns the document
    it wants written; it may raise :class:`RulesWriteError` for validation that
    can only be decided against that snapshot (duplicate ids, missing rules).
    """
    path = rules_path or resolve_rules_file()
    with rules_file_lock(path):
        exists = path.is_file()
        before_bytes = path.read_bytes() if exists else b""
        etag = etag_for_bytes(before_bytes) if exists else ABSENT_ETAG
        mode = _file_mode(path) if exists else None
        try:
            before_text = before_bytes.decode("utf-8") if exists else ""
        except UnicodeDecodeError as exc:
            raise RulesWriteError(
                "rules_file_unreadable", f"规则文件不是有效的 UTF-8 文本：{exc}", status=500
            ) from exc

        _check_if_match(if_match, etag, require_if_match)

        try:
            before_data = (yaml.safe_load(before_text) or {}) if exists else {}
        except yaml.YAMLError as exc:
            raise RulesWriteError(
                "rules_file_invalid_yaml", f"当前规则文件无法解析：{exc}", status=500
            ) from exc
        if not isinstance(before_data, dict):
            raise RulesWriteError("rules_file_invalid_yaml", "规则文件不是映射结构", status=500)

        # The builder mutates the document it is handed, so it gets its own copy:
        # the pristine parse is what "which regexes did this write change?" is
        # measured against.
        snapshot = RulesSnapshot(
            path=path,
            exists=exists,
            text=before_text,
            data=copy.deepcopy(before_data),
            etag=etag,
        )
        try:
            change = build(snapshot)
        except RulesWriteError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise RulesWriteError(
                "rules_build_failed", f"构建新规则文档失败：{exc}", status=500
            ) from exc

        after_text = change.text
        if after_text is None:
            if exists:
                raise RulesWriteError(
                    "rules_patch_unsupported",
                    "当前规则文件的写法无法在保留注释的前提下安全修改，已放弃写入（文件未改动）",
                )
            after_text = yaml.dump(
                change.expected, allow_unicode=True, default_flow_style=False, sort_keys=False
            )

        _verify_patch(snapshot, change, after_text)

        signature, failures = compile_redaction_layers(change.expected)
        incoming = changed_regexes(before_data, change.expected)
        _reject_uncompilable(failures, incoming)
        _reject_new_malformed_entries(before_data, change.expected)
        _probe_changed_regexes(incoming)

        if not path.parent.is_dir():
            # Creating the tree here is how the console used to conjure a shadow
            # rules file the runtime never reads. A missing directory means the
            # path is wrong, and that is worth an error, not a mkdir.
            raise RulesWriteError(
                "rules_dir_missing",
                f"规则文件所在目录不存在：{path.parent}（请检查 AEGIS_SECURITY_RULES_PATH）",
                status=500,
            )

        after_bytes = after_text.encode("utf-8")
        if exists and after_bytes == before_bytes:
            # Nothing to write: no backup, no reload, no new ETag. Saving an
            # unchanged document would still rotate a backup out of the window.
            write_audit({
                "event": event,
                "actor_ip": actor,
                "rules_file": str(path),
                "result": "ok",
                "no_change": True,
                "etag": etag,
                **change.audit,
            })
            return {"etag": etag, "reload": None, "backup": None, **change.payload}

        backup = create_backup(path, before_bytes, mode) if exists else None
        _atomic_write(path, after_bytes, mode)
        reload_result = _reload_rules()
        problems = _verify_applied(
            path, after_bytes, signature, reload_result, change.expected
        )

        base_audit = {
            "event": event,
            "actor_ip": actor,
            "rules_file": str(path),
            "backup": backup.name if backup else None,
            **change.audit,
        }
        if problems:
            rollback = _compare_and_restore(path, after_bytes, before_bytes, exists, mode)
            write_audit({
                **base_audit,
                "result": "failed",
                "failure_stage": "post_write_verification",
                "problems": problems,
                "reload": reload_result,
                "rollback": rollback,
            })
            logger.error(
                "rules write verification failed path=%s problems=%s rollback=%s",
                path, problems, rollback,
            )
            if rollback == "not_restored_concurrent_write":
                raise RulesWriteError(
                    "concurrent_write_detected",
                    "写入校验失败，且磁盘已被其他写入者变更，未执行回滚；请刷新后人工核对规则文件",
                    status=409,
                    extra={"problems": problems, "rollback": rollback, "reload": reload_result},
                )
            raise RulesWriteError(
                "rules_write_verification_failed",
                "写入后的校验未通过，已回滚到写入前的规则文件",
                status=500,
                extra={"problems": problems, "rollback": rollback, "reload": reload_result},
            )

        new_etag = etag_for_bytes(after_bytes)
        write_audit({
            **base_audit,
            "result": "ok",
            "etag": new_etag,
            "reload": reload_result,
        })
        return {
            "etag": new_etag,
            "reload": reload_result,
            "backup": backup.name if backup else None,
            **change.payload,
        }
