"""One bounded, exact-owned positive GET; no cleanup or IAM-management path.

Manual hosted credential validation only. Default invocation is inert. Resource
identity and the admitted Access Key fingerprint arrive through private Actions
configuration; no real identifiers or credentials belong in this source.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
import uuid

ACCESS_ENV = "NEXSIGHT_TEARDOWN_ACCESS_KEY"
SECRET_ENV = "NEXSIGHT_TEARDOWN_SECRET_KEY"
PROJECT_ENV = "NEXSIGHT_TEARDOWN_EXPECTED_PROJECT"
CONFIG_ENV = "NEXSIGHT_CREDENTIAL_CHECK_CONFIG_JSON"
FIELDS = {"schema_version", "project_id", "application_id", "zone", "security_group_id",
          "expected_access_key_sha256", "authorization_start_utc", "authorization_end_utc",
          "application_binding"}
MAX_BODY = 65536
TIMEOUT_SECONDS = 8


class Stop(ValueError):
    def __init__(self, code, http_status=None):
        super().__init__(code)
        self.http_status = http_status


def require(condition, code):
    if not condition:
        raise Stop(code)


class PublicParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, '{"result":"INCONCLUSIVE","http_status":null,"reason":"PUBLIC_ARGUMENTS_INVALID"}\n')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _response, code, _message, _headers, _url):
        raise Stop("REDIRECT_FORBIDDEN", code)


def utc_now():
    return datetime.now(timezone.utc)


def canonical_id(value):
    try:
        parsed = uuid.UUID(value)
    except Exception:
        raise Stop("CANONICAL_IDENTIFIER_REQUIRED") from None
    require(type(value) is str and str(parsed) == value and parsed.int != 0,
            "CANONICAL_IDENTIFIER_REQUIRED")
    return value


def decode(raw, limit):
    require(type(raw) is str and 0 < len(raw.encode("utf-8")) <= limit,
            "BOUNDED_JSON_REQUIRED")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_FIELD")
            result[key] = value
        return result

    def constant(_value):
        raise Stop("NONFINITE_JSON")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except Stop:
        raise
    except Exception:
        raise Stop("MALFORMED_JSON") from None


def timestamp(value):
    require(type(value) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value),
        "EXPLICIT_UTC_WINDOW_REQUIRED")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except Exception:
        raise Stop("EXPLICIT_UTC_WINDOW_REQUIRED") from None


def validate_config(raw, expected_project, now):
    value = decode(raw, 8192)
    require(type(value) is dict and value.keys() == FIELDS, "EXACT_CHECK_SCHEMA_REQUIRED")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1,
            "CHECK_SCHEMA_VERSION_REQUIRED")
    project = canonical_id(expected_project)
    require(canonical_id(value["project_id"]) == project, "INDEPENDENT_PROJECT_MISMATCH")
    canonical_id(value["application_id"])
    canonical_id(value["security_group_id"])
    require(value["security_group_id"] != project and value["zone"] == "pl-waw-2",
            "EXACT_POSITIVE_RESOURCE_REQUIRED")
    require(value["application_binding"] == "OPERATOR_ATTESTED_NOT_API_VERIFIED",
            "HONEST_APPLICATION_BINDING_REQUIRED")
    require(type(value["expected_access_key_sha256"]) is str and re.fullmatch(
        r"[a-f0-9]{64}", value["expected_access_key_sha256"]) and
        value["expected_access_key_sha256"] != "0" * 64, "PINNED_ACCESS_IDENTIFIER_REQUIRED")
    start, end = timestamp(value["authorization_start_utc"]), timestamp(value["authorization_end_utc"])
    require(isinstance(now, datetime) and now.utcoffset() == timedelta(0), "UTC_CLOCK_REQUIRED")
    require(timedelta(0) < end - start <= timedelta(minutes=30) and start <= now < end,
            "BOUNDED_CHECK_WINDOW_REQUIRED")
    require(end - now >= timedelta(seconds=10), "CHECK_WINDOW_HEADROOM_REQUIRED")
    return value, end


def bounded_body(response, started, end, *, monotonic, now):
    read1 = getattr(response, "read1", None)
    require(callable(read1), "BOUNDED_READER_REQUIRED")
    chunks, length = [], 0
    while True:
        require(monotonic() - started < TIMEOUT_SECONDS and now() < end,
                "RESPONSE_DEADLINE_EXCEEDED")
        chunk = read1(min(16384, MAX_BODY + 1 - length))
        require(type(chunk) is bytes, "RESPONSE_BYTES_REQUIRED")
        length += len(chunk)
        require(length <= MAX_BODY, "RESPONSE_SIZE_EXCEEDED")
        require(monotonic() - started < TIMEOUT_SECONDS and now() < end,
                "RESPONSE_DEADLINE_EXCEEDED")
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def status_reason(status):
    return {401: "CREDENTIAL_REJECTED", 403: "PERMISSION_DENIED", 404: "POSITIVE_RESOURCE_NOT_FOUND",
            408: "PROVIDER_TIMEOUT", 429: "RATE_LIMITED", 504: "PROVIDER_TIMEOUT"}.get(
                status, "REDIRECT_REJECTED" if 300 <= status < 400 else "UNEXPECTED_HTTP_STATUS")


def check(value, access, secret, end, *, opener=None, monotonic=time.monotonic, now=utc_now):
    require(all(type(item) is str and re.fullmatch(r"[A-Za-z0-9_-]{10,256}", item)
                for item in (access, secret)), "CREDENTIAL_FORMAT_REQUIRED")
    require(hmac.compare_digest(hashlib.sha256(access.encode("ascii")).hexdigest(),
                                value["expected_access_key_sha256"]), "REPLACEMENT_ACCESS_IDENTIFIER_MISMATCH")
    require(now() < end, "CHECK_AUTHORIZATION_EXPIRED")
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    path = "/instance/v1/zones/" + value["zone"] + "/security_groups/" + value["security_group_id"]
    request = urllib.request.Request("https://api.scaleway.com" + path, method="GET",
        headers={"X-Auth-Token": secret, "Accept": "application/json"})
    started = monotonic()
    try:
        response = opener.open(request, timeout=TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        require(type(status) is int and 100 <= status <= 599, "MALFORMED_HTTP_STATUS")
        return {"result": "FAIL", "http_status": status, "reason": status_reason(status)}
    except (TimeoutError, socket.timeout):
        raise Stop("TRANSPORT_TIMEOUT") from None
    except urllib.error.URLError as error:
        raise Stop("TRANSPORT_TIMEOUT" if isinstance(error.reason, TimeoutError) else
                   "TLS_FAILURE" if isinstance(error.reason, ssl.SSLError) else "TRANSPORT_FAILURE") from None
    except ssl.SSLError:
        raise Stop("TLS_FAILURE") from None
    except Stop:
        raise
    except Exception:
        raise Stop("TRANSPORT_FAILURE") from None
    status = None
    try:
        with response:
            status = response.status
            require(type(status) is int and 100 <= status <= 599, "MALFORMED_HTTP_STATUS")
            if status != 200:
                return {"result": "FAIL", "http_status": status, "reason": status_reason(status)}
            raw = bounded_body(response, started, end, monotonic=monotonic, now=now)
            try:
                payload = decode(raw.decode("utf-8"), MAX_BODY)
            except UnicodeError:
                raise Stop("MALFORMED_RESPONSE_ENCODING") from None
            require(type(payload) is dict and type(payload.get("security_group")) is dict,
                    "POSITIVE_RESPONSE_SCHEMA_INVALID")
            group = payload["security_group"]
            require(group.get("id") == value["security_group_id"] and group.get("project") == value["project_id"],
                    "POSITIVE_RESOURCE_IDENTITY_MISMATCH")
            return {"result": "PASS", "http_status": 200, "reason": None}
    except Stop as error:
        code = status if type(status) is int and 100 <= status <= 599 else None
        raise Stop(str(error), code) from None
    except (TimeoutError, socket.timeout):
        raise Stop("RESPONSE_TIMEOUT", status if type(status) is int else None) from None
    except Exception:
        raise Stop("RESPONSE_TRANSPORT_FAILURE", status if type(status) is int else None) from None


def main(argv=None, *, environment=None, now=utc_now, opener=None, monotonic=time.monotonic):
    parser = PublicParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print('{"result":"INCONCLUSIVE","http_status":null,"reason":"INERT_NO_CREDENTIAL_ACCESS_NO_HTTP"}')
        return 0
    environment = os.environ if environment is None else environment
    access = secret = value = None
    try:
        value, end = validate_config(environment.pop(CONFIG_ENV, None), environment.pop(PROJECT_ENV, None), now())
        access, secret = environment.pop(ACCESS_ENV, None), environment.pop(SECRET_ENV, None)
        result = check(value, access, secret, end, opener=opener, monotonic=monotonic, now=now)
    except Stop as error:
        code = str(error)
        reason = code if re.fullmatch(r"[A-Z][A-Z0-9_]{3,100}", code) else "UNEXPECTED_SAFE_STOP"
        status = error.http_status
        status = status if type(status) is int and 100 <= status <= 599 else None
        result = {"result": "INCONCLUSIVE", "http_status": status, "reason": reason}
    except Exception:
        result = {"result": "INCONCLUSIVE", "http_status": None, "reason": "UNEXPECTED_SAFE_STOP"}
    finally:
        access = secret = None
        if isinstance(value, dict):
            value.clear()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
