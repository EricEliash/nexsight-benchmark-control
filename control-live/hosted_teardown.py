"""PREPARED ONLY: portable private-secret wrapper for the reviewed executor.

No workflow/key upload, deployment or arming is performed by this file. Default
is inert. Publish only the reviewed controller bundle, never product/model/data.
The live IAM, independent scheduler and paid-run admission remain external gates.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import uuid
import zlib

ACK = "I_AUTHORIZE_ONLY_THE_PINNED_DISPOSABLE_SCALEWAY_LEDGER_TEARDOWN"
CONTROL_ENV = "NEXSIGHT_TEARDOWN_CONTROL_JSON"
LEDGER_ENV = "NEXSIGHT_TEARDOWN_LEDGER_JSON"
ACCESS_ENV = "NEXSIGHT_TEARDOWN_ACCESS_KEY"
SECRET_ENV = "NEXSIGHT_TEARDOWN_SECRET_KEY"
EXPECTED_PROJECT_ENV = "NEXSIGHT_TEARDOWN_EXPECTED_PROJECT"
SOURCE_BUNDLE_ENV = "NEXSIGHT_TEARDOWN_SOURCE_BUNDLE"
CONTROL_FIELDS = {"schema_version", "enabled", "project_id", "lab_id", "ack",
                  "window_start_utc", "window_end_utc", "adapter_sha256",
                  "executor_sha256", "cleanup_sha256", "source_bundle_sha256", "ledger_sha256", "credential_use_cap_utc"}
SOURCE_PATHS = {"native/scaleway_teardown_executor.py": "executor_sha256", "cleanup.py": "cleanup_sha256"}


class Blocked(ValueError):
    """Only constant adapter reason codes; never protected input or raw errors."""


def require(condition, code):
    if not condition:
        raise Blocked(code)


def load_json(raw, limit):
    require(isinstance(raw, str) and 0 < len(raw.encode("utf-8")) <= limit,
            "BOUNDED_PRIVATE_JSON_REQUIRED")

    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "DUPLICATE_PRIVATE_JSON_FIELD")
            result[key] = value
        return result

    def constant(_value):
        raise Blocked("NONFINITE_PRIVATE_JSON")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except Blocked:
        raise
    except Exception:
        raise Blocked("INVALID_PRIVATE_JSON") from None


def utc(value):
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value), "EXPLICIT_UTC_WINDOW_REQUIRED")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise Blocked("EXPLICIT_UTC_WINDOW_REQUIRED") from None


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
            and value != "0" * 64, "INDEPENDENT_SOURCE_AND_LEDGER_HASHES_REQUIRED")
    return value


def unpack_sources(control, source_bundle):
    """Decode ONLY two source files. No extractall, arbitrary paths or binaries."""
    require(isinstance(source_bundle, str) and 0 < len(source_bundle) <= 48 * 1024
            and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", source_bundle), "BOUNDED_PRIVATE_SOURCE_BUNDLE_REQUIRED")
    require(hashlib.sha256(source_bundle.encode("ascii")).hexdigest() == digest(control["source_bundle_sha256"]),
            "PINNED_PRIVATE_SOURCE_BUNDLE_CHANGED")
    try:
        packed = base64.b64decode(source_bundle, validate=True)
        inflater = zlib.decompressobj()
        raw = inflater.decompress(packed, 256 * 1024 + 1)
        require(len(raw) <= 256 * 1024 and inflater.eof and not inflater.unused_data
                and not inflater.unconsumed_tail, "SOURCE_BUNDLE_DECOMPRESSION_BOUNDARY_INVALID")
        payload = load_json(raw.decode("utf-8"), 256 * 1024)
        require(isinstance(payload, dict) and payload.keys() == {"schema_version", "files"}
                and type(payload["schema_version"]) is int and payload["schema_version"] == 1
                and isinstance(payload["files"], dict) and payload["files"].keys() == SOURCE_PATHS.keys(),
                "EXACT_TWO_SOURCE_PATHS_REQUIRED")
        files = {}
        for path, key in SOURCE_PATHS.items():
            encoded = payload["files"][path]
            require(isinstance(encoded, str) and len(encoded) <= 192 * 1024, "SOURCE_FILE_SIZE_INVALID")
            data = base64.b64decode(encoded, validate=True)
            require(0 < len(data) <= 128 * 1024 and hashlib.sha256(data).hexdigest() == digest(control[key]),
                    "PINNED_CONTROLLER_SOURCE_CHANGED")
            data.decode("utf-8")
            files[path] = data
        return files
    except Blocked:
        raise
    except Exception:
        raise Blocked("INVALID_PRIVATE_SOURCE_BUNDLE") from None


def load_executor(control, source_bundle):
    source = Path(__file__)
    require(source.is_file() and not any(part.is_symlink() or getattr(part, "is_junction", lambda: False)()
            for part in (source, *source.parents)), "EXACT_NONLINK_CONTROLLER_SOURCE_REQUIRED")
    require(hashlib.sha256(source.read_bytes()).hexdigest() == digest(control["adapter_sha256"]),
            "PINNED_CONTROLLER_SOURCE_CHANGED")
    files = unpack_sources(control, source_bundle)  # Verify every byte BEFORE writing/importing.
    with tempfile.TemporaryDirectory(prefix="exact-ledger-controller-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        (root / "native").mkdir(mode=0o700)
        for relative, data in files.items():
            destination = root / relative
            with destination.open("xb") as handle:
                os.chmod(destination, 0o700)
                handle.write(data)
        # Preserve the exact reviewed dependency layout; no source substitutions.
        spec = importlib.util.spec_from_file_location("reviewed_hosted_teardown_executor", root / "native/scaleway_teardown_executor.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Its imported code remains in memory. Remove only this owned temporary
        # source directory; no credential/config/data files are ever written.
    require(module.ACK == ACK and module.CLEANUP_SHA256 == control["cleanup_sha256"],
            "REVIEWED_EXECUTOR_CONTRACT_CHANGED")
    return module


def execute(control, ledger_raw, *, access_key, secret_key, source_bundle, expected_project, clock, loader=load_executor):
    """Actual calls occur only through unchanged executor.run/Client after gates."""
    require(isinstance(control, dict) and control.keys() == CONTROL_FIELDS,
            "EXACT_CONTROL_SCHEMA_REQUIRED")
    require(type(control["schema_version"]) is int and control["schema_version"] == 1
            and control["enabled"] is True, "EXPLICIT_CONTROL_ARM_REQUIRED")
    try:
        parsed_project = uuid.UUID(expected_project)
    except (ValueError, TypeError, AttributeError):
        raise Blocked("INDEPENDENT_EXPECTED_PROJECT_REQUIRED") from None
    require(parsed_project.int != 0 and str(parsed_project) == expected_project,
            "INDEPENDENT_EXPECTED_PROJECT_REQUIRED")
    require(control["project_id"] == expected_project and control["ack"] == ACK,
            "EXACT_PROJECT_AND_CLEANUP_ACK_REQUIRED")
    require(isinstance(control["lab_id"], str) and re.fullmatch(
        r"nexsight-bench-[a-z0-9-]{8,48}", control["lab_id"]), "EXACT_LAB_REQUIRED")
    for name in ("adapter_sha256", "executor_sha256", "cleanup_sha256", "source_bundle_sha256", "ledger_sha256"):
        digest(control[name])
    observed = clock()
    require(isinstance(observed, datetime) and observed.utcoffset() == timedelta(0), "UTC_CLOCK_REQUIRED")
    start, end = utc(control["window_start_utc"]), utc(control["window_end_utc"])
    require(timedelta(0) < end - start <= timedelta(hours=6) and start <= observed < end,
            "EXPLICIT_FINITE_CONTROL_WINDOW_REQUIRED")
    ledger = load_json(ledger_raw, 65536)
    require(hashlib.sha256(ledger_raw.encode("utf-8")).hexdigest() == control["ledger_sha256"],
            "PINNED_LEDGER_CHANGED")
    executor = loader(control, source_bundle)
    try:
        executor.validate(ledger, expected_project=expected_project, expected_lab=control["lab_id"])
        allocated = utc(ledger["allocated_at_utc"])
        deadline = utc(ledger["allocation_deadline_utc"])
        require(start <= allocated <= observed and deadline <= end,
                "ALLOCATION_OUTSIDE_CONTROL_WINDOW")
        require(observed >= utc(ledger["teardown_at_utc"]), "SCHEDULED_TEARDOWN_NOT_DUE")
        require(observed + executor.CREDENTIAL_ATTEMPT_WINDOW <= end,
                "CONTROL_WINDOW_CANNOT_COVER_EXISTING_ATTEMPT")
        # Explicit hosted input format, not a fallback for Windows DPAPI. The
        # operator enters two GitHub encrypted secrets, never a hand-built key
        # JSON. This envelope is assembled only in memory and reuses the exact
        # existing strict project/schema/local-use-cap consumer.
        envelope = {"project_id": expected_project, "access_key": access_key,
                    "secret_key": secret_key, "expires_at_utc": control["credential_use_cap_utc"]}
        credential_raw = None
        try:
            credential_raw = json.dumps(envelope, allow_nan=False)
            secret = executor.credential_secret_from_envelope(credential_raw.encode("utf-8"),
                expected_project=ledger["project_id"], allocation_deadline_utc=ledger["allocation_deadline_utc"],
                current_utc=observed)
            require(utc(envelope["expires_at_utc"]) >= end, "LOCAL_KEY_CAP_CANNOT_COVER_CONTROL_WINDOW")
            client = executor.Client(secret)
            try:
                result = executor.run(client, ledger, expected_project=expected_project,
                    expected_lab=control["lab_id"], ack=ACK, clock=clock)
            finally:
                client.secret = None
                secret = None
        finally:
            if isinstance(envelope, dict):
                envelope.clear()
            credential_raw = None
            access_key = None
            secret_key = None
    except Blocked:
        raise
    except executor.Error:
        raise Blocked("REVIEWED_EXECUTOR_STOPPED_NO_ABSENCE_CLAIM") from None
    require(isinstance(result, dict) and result.get("status") ==
            "PINNED_LEDGER_ABSENT_IN_ALL_SUPPORTED_PRODUCT_LISTS" and
            result.get("project_deleted") is False and result.get("financial_cap_guaranteed") is False,
            "REVIEWED_EXECUTOR_SUCCESS_CONTRACT_CHANGED")
    # Public logs intentionally contain no project/lab/resource IDs, addresses,
    # config values, access identifier, key, provider body or deletion event list.
    return {"status": "REVIEWED_PINNED_LEDGER_ABSENCE_CONFIRMED",
            "owned_ledger_count": len(ledger["resources"]),
            "complete_product_types": result["product_lists_complete"],
            "complete_inventory_scopes": result["product_inventory_scopes_complete"],
            "unrelated_resources_preserved": result["unrelated_resources_preserved"],
            "api_calls": result["api_calls"], "financial_cap_guaranteed": False,
            "project_deleted": False, "provider_key_expiry_verified": False}


def main(argv=None, *, environment=None, clock=lambda: datetime.now(timezone.utc)):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--execute", action="store_true")
    args = cli.parse_args(argv)
    if not args.execute:
        print('{"status":"INERT_NO_SECRETS_NO_PROVIDER_NO_ARMING"}')
        return 0
    environment = os.environ if environment is None else environment
    control = None
    try:
        control = load_json(environment.pop(CONTROL_ENV, None), 8192)
        if isinstance(control, dict) and control.get("enabled") is False:
            print('{"status":"DISARMED_NO_CREDENTIAL_ACCESS_NO_PROVIDER"}')
            return 0
        ledger_raw = environment.pop(LEDGER_ENV, None)
        access_key = environment.pop(ACCESS_ENV, None)
        secret_key = environment.pop(SECRET_ENV, None)
        expected_project = environment.pop(EXPECTED_PROJECT_ENV, None)
        source_bundle = environment.pop(SOURCE_BUNDLE_ENV, None)
        result = execute(control, ledger_raw, access_key=access_key, secret_key=secret_key,
                         source_bundle=source_bundle, expected_project=expected_project, clock=clock)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except Blocked as error:
        print(json.dumps({"status": "STOPPED_NO_GLOBAL_ABSENCE_CLAIM", "reason": str(error)}, sort_keys=True))
        return 2
    except Exception:
        print('{"status":"STOPPED_NO_GLOBAL_ABSENCE_CLAIM","reason":"UNEXPECTED_SAFE_STOP"}')
        return 2
    finally:
        # Never pass secrets to child processes, files, artifacts or caller output.
        ledger_raw = None
        access_key = None
        secret_key = None
        source_bundle = None
        if isinstance(control, dict):
            control.clear()


if __name__ == "__main__":
    raise SystemExit(main())
