from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .models import PolicyError
from .simulator import SimulationPolicy, TraceError, simulate_trace


class _ArgumentError(Exception):
    pass


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _ArgumentError(message)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _ArgumentParser(add_help=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--compare")
    try:
        arguments = parser.parse_args(argv)
        baseline = SimulationPolicy.parse(_read_text(arguments.policy))
        candidate = (
            SimulationPolicy.parse(_read_text(arguments.compare)) if arguments.compare is not None else None
        )
        reports = simulate_trace(baseline, candidate, _read_text(arguments.trace))
    except TraceError as error:
        return _write_error(error.code, error.line)
    except PolicyError as error:
        return _write_error(error.code, None)
    except _ArgumentError:
        return _write_error("invalid_arguments", None)
    except (OSError, UnicodeError):
        return _write_error("io_error", None)

    try:
        output = b"".join(
            (json.dumps(report.to_dict(), separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
            for report in reports
        )
        written = sys.stdout.buffer.write(output)
        if written != len(output):
            raise OSError("unable to write complete simulator output")
        sys.stdout.buffer.flush()
    except (OSError, UnicodeError, TypeError, ValueError):
        return _write_error("io_error", None)
    return 0


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _write_error(code: str, line: int | None) -> int:
    sys.stderr.write(json.dumps({"code": code, "line": line}, separators=(",", ":")) + "\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
