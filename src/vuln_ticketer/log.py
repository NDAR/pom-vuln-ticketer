import json
import logging
import sys

_STANDARD = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"level": record.levelname, "message": record.getMessage()}
        out.update({k: v for k, v in record.__dict__.items() if k not in _STANDARD})
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


class _StdoutHandler(logging.Handler):
    # Resolves sys.stdout at emit time so Lambda and test capture both see it.
    def emit(self, record: logging.LogRecord) -> None:
        sys.stdout.write(self.format(record) + "\n")


def get_logger(name: str) -> logging.Logger:
    """Logger emitting one structured JSON line per record (captured by CloudWatch Logs)."""
    logger = logging.getLogger(f"vuln_ticketer.{name}")
    if not logger.handlers:
        handler = _StdoutHandler()
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
