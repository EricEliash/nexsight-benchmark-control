"""Finite secret-free wait only. Success wakes the separate guarded workflow.

This code has no provider, credential, checkout, dispatch or cleanup capability.
Missing/invalid/past due time fails; it never authorizes resource deletion.
"""
from datetime import datetime, timezone
import json
import os
import re
import time

MAX_WAIT_SECONDS = 210 * 60
MAX_ELAPSED_SECONDS = MAX_WAIT_SECONDS + 15
CLOCK_SKEW_SECONDS = 5.0


class Rejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def utc_now():
    return datetime.now(timezone.utc)


def wait_until(raw_due, *, clock=utc_now, monotonic=time.monotonic, sleep=time.sleep):
    require(isinstance(raw_due, str) and len(raw_due) <= 32 and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", raw_due),
        "EXPLICIT_UTC_DUE_REQUIRED")
    try:
        due = datetime.fromisoformat(raw_due[:-1] + "+00:00")
    except ValueError:
        raise Rejected("INVALID_UTC_DUE") from None
    start_wall, start_mono = clock(), monotonic()
    require(isinstance(start_wall, datetime) and start_wall.utcoffset() is not None
            and start_wall.utcoffset().total_seconds() == 0, "UTC_CLOCK_REQUIRED")
    delay = (due - start_wall).total_seconds()
    require(0 < delay <= MAX_WAIT_SECONDS, "FUTURE_DUE_WITHIN_210_MINUTES_REQUIRED")
    previous_mono = start_mono
    while True:
        wall, mono = clock(), monotonic()
        require(isinstance(wall, datetime) and wall.utcoffset() is not None
                and wall.utcoffset().total_seconds() == 0, "UTC_CLOCK_REQUIRED")
        elapsed = mono - start_mono
        require(mono >= previous_mono and 0 <= elapsed <= MAX_ELAPSED_SECONDS,
                "MONOTONIC_WAIT_BOUNDARY_REQUIRED")
        require(abs((wall - start_wall).total_seconds() - elapsed) <= CLOCK_SKEW_SECONDS,
                "UTC_MONOTONIC_CLOCK_DIVERGED")
        if wall >= due and elapsed >= delay:
            return {"status": "FINITE_WAKEUP_DUE_NO_CLOUD_CALLS",
                    "waited_seconds": round(elapsed, 3), "cloud_calls": 0,
                    "secrets_read": False, "cleanup_executed": False}
        previous_mono = mono
        remaining = max(delay - elapsed, (due - wall).total_seconds())
        sleep(min(15.0, max(0.05, remaining)))


def main(environment=None):
    try:
        environment = os.environ if environment is None else environment
        result = wait_until(environment.get("WAKEUP_DUE_UTC", ""))
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except Rejected as error:
        print(json.dumps({"status": "WAKEUP_REJECTED_NO_CLOUD_CALLS", "reason": str(error)},
                         sort_keys=True))
        return 2
    except Exception:
        print('{"status":"WAKEUP_REJECTED_NO_CLOUD_CALLS","reason":"UNEXPECTED_SAFE_STOP"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
