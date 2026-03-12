import logging

from aegisgate.util.logger import DailyRotatingFileHandler


def test_daily_rotating_file_handler_disables_file_output_after_permission_error(monkeypatch, tmp_path):
    handler = DailyRotatingFileHandler(base_dir=tmp_path / "logs")
    handler.setFormatter(logging.Formatter("%(message)s"))

    def _raise_permission_error(*args, **kwargs):
        raise PermissionError("read-only")

    monkeypatch.setattr("aegisgate.util.logger.RotatingFileHandler", _raise_permission_error)

    handler.emit(logging.makeLogRecord({"msg": "first", "levelno": logging.INFO, "levelname": "INFO"}))
    handler.emit(logging.makeLogRecord({"msg": "second", "levelno": logging.INFO, "levelname": "INFO"}))

    assert handler._use_fallback is True
    assert handler._inner is None
