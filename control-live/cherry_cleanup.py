#!/usr/bin/env python3
"""Inert-by-default, exact-ledger Cherry Servers cleanup adapter.

Official API contract: https://api.cherryservers.com/doc/ (v1, reviewed 2026-10-29).
Only GET and exact-ID DELETE for servers, backup-storages and tagged floating IPs
are supported. Exact enrolled primary/private IPv4 and IPv6/64 server children
are passively verified and released by parent termination, never DELETEd here.
No provisioning, key management, team/project deletion, bulk deletion or retries.
EBS, custom/unknown subnets and load balancers MUST remain absent.

Inputs are private environment variables, never command arguments or output:
NEXSIGHT_CHERRY_CONTROL_JSON, NEXSIGHT_CHERRY_LEDGER_JSON, CHERRY_API_TOKEN.
The caller must independently pin this source and the exact ledger digest. This
adapter does not enroll unknown resources or establish a hosted wake-up itself.
An empty-ledger probe is NOT proof that future paid resources are protected.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

API = "https://api.cherryservers.com"
REGION = 3  # Chicago, from the reviewed portal quotation; live probe rechecks it.
PLANS = {"dut": 739, "generator": 747}
ENDPOINTS = {"server": "servers", "backup_storage": "backup-storages", "ip": "ips",
             "managed_ip": "ips", "managed_ipv6_subnet": "subnets"}
MANAGED = {"managed_ip", "managed_ipv6_subnet"}
INVENTORIES = ("servers", "backup-storages", "ips", "storages", "subnets", "load-balancers")
SENSITIVE = {"password", "secret", "token", "access_token", "refresh_token", "bmc", "user_data", "userdata", "console"}
SAFE_FIELDS = {
    "server": "id,href,hostname,project,plan,region,tags,backup_storage,storage",
    "backup_storage": "id,href",
    "ip": "id,href,project,region,tags,type",
    "managed_ip": "id,href,project,region,assigned_to,type,address_family",
    "managed_ipv6_subnet": "id,href,project,region,assigned_to,address_family,cidr",
}


class GuardError(Exception):
    """Stable reason codes only; never include provider bodies or credential data."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise GuardError(code)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse_json(raw: str | bytes):
    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise GuardError("MALFORMED_JSON") from None


def utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.utcoffset() == timedelta(0), "UTC_REQUIRED")
        return result
    except (ValueError, TypeError, AttributeError):
        raise GuardError("INVALID_TIMESTAMP") from None


def number(value) -> int:
    require(type(value) is int and value > 0, "INVALID_NUMERIC_ID")
    return value


def reject_sensitive(value):
    if isinstance(value, dict):
        require(not (set(k.lower() for k in value) & SENSITIVE), "SENSITIVE_RESPONSE_FIELD")
        for nested in value.values():
            reject_sensitive(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_sensitive(nested)


def href(value, path: str) -> None:
    # Live v1 responses use exact relative self-links without the API version.
    # Never follow these links or normalize foreign hosts, queries or traversal.
    require(value in (API + path, path.removeprefix("/v1")), "RESOURCE_HREF_MISMATCH")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Api:
    """Fixed origin, TLS-verified, no redirects/proxies, bounded response, no logs."""

    def __init__(self, token: str, deadline: datetime):
        require(isinstance(token, str) and 10 <= len(token) <= 4096, "TOKEN_REQUIRED")
        require(not any(ch.isspace() for ch in token), "INVALID_TOKEN_FORMAT")
        self._token = token
        self._deadline = deadline
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        self._last_request = 0.0
        self._hard_end = time.monotonic() + 20 * 60

    def request(self, method: str, path: str, fields: str | None = None, offset: int | None = None,
                status_filter: str | None = None):
        require(datetime.now(timezone.utc) < self._deadline, "REQUEST_WINDOW_EXPIRED")
        require(time.monotonic() < self._hard_end, "API_EXECUTION_BUDGET_EXPIRED")
        require(method in {"GET", "DELETE"}, "METHOD_FORBIDDEN")
        require(re.fullmatch(r"/v1/[a-z0-9/-]+", path) is not None, "PATH_FORBIDDEN")
        if method == "DELETE":
            require(re.fullmatch(r"/v1/(servers|backup-storages)/[1-9][0-9]*|/v1/ips/[a-f0-9-]{36}", path) is not None, "DELETE_PATH_FORBIDDEN")
            require(fields is None and offset is None and status_filter is None, "DELETE_QUERY_FORBIDDEN")
        params = {}
        if fields is not None:
            params["fields"] = fields
        if offset is not None:
            params.update(limit=100, offset=offset)
        if status_filter is not None:
            require(status_filter in {"assigned", "available"} and method == "GET"
                    and re.fullmatch(r"/v1/(?:projects/[1-9][0-9]*/ips|servers/[1-9][0-9]*/(?:ips|subnets))", path),
                    "STATUS_FILTER_FORBIDDEN")
            # Official cherrygo GetOptions.Encode uses array keys even for a
            # singleton: status[]=assigned, not the scalar status=assigned.
            params["status[]"] = status_filter
        url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
        delay = 0.3 - (time.monotonic() - self._last_request)
        if delay > 0:
            time.sleep(delay)
        require(datetime.now(timezone.utc) < self._deadline, "REQUEST_WINDOW_EXPIRED")
        require(time.monotonic() < self._hard_end, "API_EXECUTION_BUDGET_EXPIRED")
        self._last_request = time.monotonic()
        request = urllib.request.Request(url, method=method, headers={
            "Authorization": "Bearer " + self._token,
            "Accept": "application/json", "User-Agent": "NexSight-exact-ledger-cleanup/1",
        })
        started = time.monotonic()
        try:
            timeout = min(15, self._hard_end-time.monotonic(),
                          (self._deadline-datetime.now(timezone.utc)).total_seconds())
            require(timeout > 0, "REQUEST_WINDOW_EXPIRED")
            with self._opener.open(request, timeout=timeout) as response:
                status = int(response.status)
                chunks, length = [], 0
                while True:
                    require(datetime.now(timezone.utc) < self._deadline, "REQUEST_WINDOW_EXPIRED")
                    require(time.monotonic() - started < 15, "HTTP_WALL_TIMEOUT")
                    require(time.monotonic() < self._hard_end, "API_EXECUTION_BUDGET_EXPIRED")
                    chunk = response.read1(65536)
                    require(datetime.now(timezone.utc) < self._deadline, "REQUEST_WINDOW_EXPIRED")
                    require(time.monotonic() - started < 15, "HTTP_WALL_TIMEOUT")
                    require(time.monotonic() < self._hard_end, "API_EXECUTION_BUDGET_EXPIRED")
                    if not chunk:
                        break
                    length += len(chunk)
                    require(length <= 2 * 1024 * 1024, "RESPONSE_TOO_LARGE")
                    chunks.append(chunk)
                body = b"".join(chunks)
                if status == 204:
                    require(not body, "NONEMPTY_204")
                    return status, None
                require("application/json" in response.headers.get("Content-Type", ""), "NON_JSON_RESPONSE")
                result = parse_json(body)
                reject_sensitive(result)
                return status, result
        except urllib.error.HTTPError as error:
            # Never read or expose the error body/URL/headers, and never retry.
            status = int(error.code)
            error.close()
            return status, None
        except (TimeoutError, socket.timeout):
            raise GuardError("HTTP_TIMEOUT") from None
        except (urllib.error.URLError, OSError, ssl.SSLError):
            raise GuardError("HTTP_TRANSPORT_FAILURE") from None


def get(api, path: str, fields: str):
    status, result = api.request("GET", path, fields)
    require(status == 200, f"HTTP_{status}")
    return result


def listing(api, path: str, fields: str = "id,href", status_filter: str | None = None) -> list:
    all_items = []
    for offset in range(0, 501, 100):
        status, items = (api.request("GET", path, fields, offset, status_filter=status_filter)
                         if status_filter is not None else api.request("GET", path, fields, offset))
        require(status == 200, f"HTTP_{status}")
        require(isinstance(items, list) and len(items) <= 100, "INVALID_LIST_SCHEMA")
        require(all(isinstance(item, dict) for item in items), "INVALID_LIST_ITEM")
        all_items.extend(items)
        if len(items) < 100:
            ids = [item.get("id") for item in all_items]
            require(len(ids) == len(set(ids)), "DUPLICATE_INVENTORY_ID")
            return all_items
    raise GuardError("INVENTORY_LIMIT")


def validate(control: dict, ledger_raw: str, now: datetime) -> dict:
    require(isinstance(control, dict) and control.get("schema_version") == 1, "CONTROL_SCHEMA")
    require(control.get("enabled") is True, "DISABLED")
    # Independent repository/environment pins, not the same untrusted config.
    try:
        expected_team = int(os.environ.get("NEXSIGHT_CHERRY_EXPECTED_TEAM", ""))
        expected_project = int(os.environ.get("NEXSIGHT_CHERRY_EXPECTED_PROJECT", ""))
    except ValueError:
        raise GuardError("INDEPENDENT_SCOPE_PINS_REQUIRED") from None
    require(number(control.get("team_id")) == expected_team and number(control.get("project_id")) == expected_project, "SCOPE_MISMATCH")
    require(control.get("region_id") == REGION, "REGION_MISMATCH")
    require(re.fullmatch(r"nexsight-[a-z0-9-]{8,64}", control.get("lab_id", "")) is not None, "LAB_ID_INVALID")
    number(control.get("expected_user_id"))
    start, end = utc(control.get("authorization_start_utc")), utc(control.get("authorization_expires_utc"))
    require(start <= now < end and timedelta(0) < end - start <= timedelta(hours=6), "AUTHORIZATION_WINDOW")
    digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    require(control.get("source_sha256") == digest, "SOURCE_PIN_MISMATCH")
    require(control.get("ledger_sha256") == hashlib.sha256(ledger_raw.encode("utf-8")).hexdigest(), "LEDGER_PIN_MISMATCH")
    ledger = parse_json(ledger_raw)
    require(isinstance(ledger, dict) and set(ledger) == {"schema_version", "lab_id", "resources"}, "LEDGER_SCHEMA")
    require(ledger["schema_version"] == 1 and ledger["lab_id"] == control["lab_id"], "LEDGER_SCOPE")
    resources = ledger["resources"]
    require(isinstance(resources, list) and len(resources) <= 12, "LEDGER_RESOURCE_LIMIT")
    keys, roles, server_ids, child_slots = set(), set(), set(), set()
    for resource in resources:
        require(isinstance(resource, dict), "LEDGER_RESOURCE_SCHEMA")
        kind = resource.get("kind")
        require(kind in ENDPOINTS, "UNSUPPORTED_RESOURCE_KIND")
        identity = resource.get("id")
        if kind in {"ip", *MANAGED}:
            require(isinstance(identity, str) and re.fullmatch(r"[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", identity) is not None, "INVALID_IP_ID")
        else:
            number(identity)
        require((ENDPOINTS[kind], identity) not in keys, "DUPLICATE_LEDGER_RESOURCE")
        keys.add((ENDPOINTS[kind], identity))
        require(resource.get("ownership_verified") is True, "UNVERIFIED_ENROLLMENT")
        if kind == "server":
            role = resource.get("role")
            require(role in PLANS and role not in roles, "ROLE_INVALID_OR_DUPLICATE")
            require(resource.get("plan_id") == PLANS[role], "UNAPPROVED_PLAN")
            require(re.fullmatch(r"nexsight-[a-z0-9-]{3,100}", resource.get("hostname", "")) is not None, "HOSTNAME_INVALID")
            roles.add(role)
            server_ids.add(identity)
        if kind in MANAGED:
            allowed = {"kind", "id", "server_id", "ownership_verified",
                       "ip_type" if kind == "managed_ip" else "cidr"}
            require(set(resource) == allowed, "MANAGED_CHILD_LEDGER_SCHEMA")
            if kind == "managed_ip":
                require(resource["ip_type"] in {"primary-ip", "private-ip"}, "MANAGED_IP_TYPE_FORBIDDEN")
                slot = resource["ip_type"]
            else:
                network = ipv6_64(resource["cidr"])
                slot = "ipv6_subnet"
                require(str(network) == resource["cidr"], "EXACT_MANAGED_IPV6_CIDR_REQUIRED")
            require((resource["server_id"], slot) not in child_slots, "MANAGED_CHILD_CARDINALITY")
            child_slots.add((resource["server_id"], slot))
    for resource in resources:
        if resource["kind"] != "server":
            require(resource.get("server_id") in server_ids, "PARENT_SERVER_NOT_ENROLLED")
        if resource["kind"] == "managed_ipv6_subnet":
            parent = next(r for r in resources if r["kind"] == "server" and r["id"] == resource["server_id"])
            require(parent["role"] in PLANS and parent["plan_id"] == PLANS[parent["role"]],
                    "MANAGED_IPV6_PARENT_FORBIDDEN")
    t0 = control.get("first_paid_at_utc")
    if resources:
        require(t0 is not None, "PAID_CLOCK_REQUIRED")
    if t0 is not None:
        allocated = utc(t0)
        require(start <= allocated <= now, "PAID_CLOCK_INVALID")
        require(utc(control.get("cleanup_due_utc")) <= allocated + timedelta(minutes=195), "CLEANUP_TOO_LATE")
        require(utc(control.get("deletion_deadline_utc")) <= allocated + timedelta(hours=4), "DELETION_TOO_LATE")
        require(allocated <= utc(control["cleanup_due_utc"]) < utc(control["deletion_deadline_utc"]) <= end, "DEADLINE_ORDER")
        require(now < utc(control["deletion_deadline_utc"]), "DELETION_WINDOW_EXPIRED")
    return ledger


def auth_scope(api, control: dict):
    team, project_id = control["team_id"], control["project_id"]
    user = get(api, "/v1/user", "id")
    require(isinstance(user, dict) and user.get("id") == control["expected_user_id"], "USER_IDENTITY_MISMATCH")
    teams = listing(api, "/v1/teams")
    require([item.get("id") for item in teams] == [team], "ACCOUNT_NOT_ISOLATED")
    projects = listing(api, f"/v1/teams/{team}/projects")
    require([item.get("id") for item in projects] == [project_id], "PROJECT_NOT_ISOLATED")
    project = get(api, f"/v1/projects/{project_id}", "id,href")
    require(isinstance(project, dict) and project.get("id") == project_id, "PROJECT_IDENTITY_MISMATCH")
    href(project.get("href"), f"/v1/projects/{project_id}")


def inventory(api, control: dict) -> dict:
    observed = {}
    for kind in INVENTORIES:
        path = f"/v1/projects/{control['project_id']}/{kind}"
        if kind == "ips":
            by_id = {}
            for state in ("assigned", "available"):
                for item in listing(api, path, status_filter=state):
                    identity = item.get("id")
                    if identity in by_id:
                        # Two sequential filtered requests are not an atomic
                        # snapshot. Union exact matching records, never hide a
                        # changed href/metadata or a duplicate within one list.
                        require(item == by_id[identity], "STATUS_INVENTORY_INCONSISTENT")
                        href(item.get("href"), f"/v1/ips/{identity}")
                    else:
                        by_id[identity] = item
            observed[kind] = list(by_id.values())
        else:
            observed[kind] = listing(api, path)
    return observed


def ipv6_64(value):
    try:
        require(isinstance(value, str), "MANAGED_IPV6_64_REQUIRED")
        network = ipaddress.IPv6Network(value, strict=True)
    except (ValueError, TypeError):
        raise GuardError("MANAGED_IPV6_64_REQUIRED") from None
    require(network.prefixlen == 64 and network.is_global, "MANAGED_IPV6_64_REQUIRED")
    return network


def verify_resource(obj: dict, resource: dict, control: dict):
    kind, identity = resource["kind"], resource["id"]
    require(isinstance(obj, dict) and obj.get("id") == identity, "RESOURCE_IDENTITY_MISMATCH")
    href(obj.get("href"), f"/v1/{ENDPOINTS[kind]}/{identity}")
    if kind == "server":
        require(obj.get("project", {}).get("id") == control["project_id"], "SERVER_PROJECT_MISMATCH")
        require(obj.get("region", {}).get("id") == REGION, "SERVER_REGION_MISMATCH")
        require(obj.get("plan", {}).get("id") == resource["plan_id"], "SERVER_PLAN_MISMATCH")
        require(obj.get("hostname") == resource["hostname"], "SERVER_HOSTNAME_MISMATCH")
        require(obj.get("tags", {}).get("nexsight_lab") == control["lab_id"], "SERVER_LAB_TAG_MISMATCH")
        require(obj.get("storage") in (None, {}, []), "UNSUPPORTED_ATTACHED_EBS")
    if kind == "ip":
        require(obj.get("project", {}).get("id") == control["project_id"], "IP_PROJECT_MISMATCH")
        require(obj.get("region", {}).get("id") == REGION, "IP_REGION_MISMATCH")
        require(obj.get("tags", {}).get("nexsight_lab") == control["lab_id"], "IP_LAB_TAG_MISMATCH")
        require(obj.get("type") == "floating-ip", "TAGGED_IP_TYPE_FORBIDDEN")
    if kind in MANAGED:
        require(obj.get("project", {}).get("id") == control["project_id"], "MANAGED_CHILD_PROJECT_MISMATCH")
        require(obj.get("region", {}).get("id") == REGION, "MANAGED_CHILD_REGION_MISMATCH")
        parent = obj.get("assigned_to")
        require(isinstance(parent, dict) and parent.get("id") == resource["server_id"], "MANAGED_CHILD_PARENT_MISMATCH")
        if "href" in parent:
            href(parent["href"], f"/v1/servers/{resource['server_id']}")
        if kind == "managed_ip":
            require(type(obj.get("address_family")) is int and obj["address_family"] == 4
                    and obj.get("type") == resource["ip_type"], "MANAGED_IPV4_TYPE_MISMATCH")
        else:
            require(type(obj.get("address_family")) is int and obj["address_family"] == 6
                    and obj.get("cidr") == resource["cidr"], "MANAGED_IPV6_CIDR_MISMATCH")
            ipv6_64(obj["cidr"])


def inventory_guard(observed, ledger):
    for unsupported in ("storages", "load-balancers"):
        require(not observed[unsupported], "UNSUPPORTED_BILLABLE_RESOURCE_PRESENT")
    enrolled = {endpoint: {r["id"] for r in ledger["resources"] if ENDPOINTS[r["kind"]] == endpoint}
                for endpoint in set(ENDPOINTS.values())}
    for endpoint, identities in enrolled.items():
        require({item.get("id") for item in observed[endpoint]} <= identities,
                "UNSUPPORTED_BILLABLE_RESOURCE_PRESENT" if endpoint == "subnets" else "UNENROLLED_RESOURCE_PRESENT")
    return enrolled


def verify_parent_membership(api, parent_id, resources):
    # Both sides of the provider relation, not a client-supplied server_id alone.
    for kind, endpoint in (("managed_ip", "ips"), ("managed_ipv6_subnet", "subnets")):
        expected = {r["id"] for r in resources if r["kind"] == kind and r["server_id"] == parent_id}
        if not expected:
            continue
        rows = listing(api, f"/v1/servers/{parent_id}/{endpoint}", status_filter="assigned")
        known = {r["id"] for r in resources if r.get("server_id") == parent_id
                 and ENDPOINTS[r["kind"]] in {"ips", "subnets"}}
        ids = {row.get("id") for row in rows}
        require(expected <= ids and ids <= known, "PROVIDER_PARENT_MEMBERSHIP_MISMATCH")


def inspect(api, control: dict, ledger: dict) -> tuple[dict, dict]:
    auth_scope(api, control)
    observed = inventory(api, control)
    enrolled = inventory_guard(observed, ledger)
    objects = {}
    absent_parents = set()
    for resource in sorted(ledger["resources"], key=lambda item: item["kind"] != "server"):
        kind, identity = resource["kind"], resource["id"]
        path = f"/v1/{ENDPOINTS[kind]}/{identity}"
        status, obj = api.request("GET", path, SAFE_FIELDS[kind])
        if status == 404:
            require(identity not in {item.get("id") for item in observed[ENDPOINTS[kind]]}, "ABSENCE_INCONSISTENT")
            if kind == "server":
                absent_parents.add(identity)
            continue
        if status == 403 and kind in MANAGED:
            require(resource["server_id"] in absent_parents
                    and identity not in {item.get("id") for item in observed[ENDPOINTS[kind]]},
                    "MANAGED_CHILD_RELEASE_NOT_PROVEN")
            continue  # Project release only, NEVER a global-record deletion claim.
        require(status == 200, f"HTTP_{status}")
        require(identity in {item.get("id") for item in observed[ENDPOINTS[kind]]}, "RESOURCE_INVENTORY_INCONSISTENT")
        verify_resource(obj, resource, control)
        objects[(kind, identity)] = obj
    for (kind, identity) in objects:
        if kind == "server":
            verify_parent_membership(api, identity, ledger["resources"])
    for resource in ledger["resources"]:
        if resource["kind"] == "backup_storage" and ("backup_storage", resource["id"]) in objects:
            parent = objects.get(("server", resource["server_id"]))
            # If the server is already absent, the protected enrolled ID plus
            # its current project inventory membership is the retained relation.
            if parent is not None:
                require(parent.get("backup_storage", {}).get("id") == resource["id"], "BACKUP_PARENT_MISMATCH")
            require(resource["id"] in {item["id"] for item in observed["backup-storages"]}, "BACKUP_PROJECT_MISMATCH")
    for (kind, _), obj in objects.items():
        if kind == "server" and obj.get("backup_storage"):
            backup_id = obj["backup_storage"].get("id")
            require(backup_id in enrolled["backup-storages"], "UNENROLLED_BACKUP_STORAGE")
    return observed, objects


def await_managed_release(api, control, ledger):
    managed = [r for r in ledger["resources"] if r["kind"] in MANAGED]
    end = time.monotonic() + 15 * 60
    while True:
        observed = inventory(api, control)
        inventory_guard(observed, ledger)
        released, parents_absent = 0, {}
        for resource in managed:
            parent_id = resource["server_id"]
            if parent_id not in parents_absent:
                parent_status, _ = api.request("GET", f"/v1/servers/{parent_id}", SAFE_FIELDS["server"])
                require(parent_status in {200, 404}, f"PARENT_ABSENCE_HTTP_{parent_status}")
                parents_absent[parent_id] = parent_status == 404
            endpoint = ENDPOINTS[resource["kind"]]
            if resource["id"] in {item.get("id") for item in observed[endpoint]}:
                continue
            status, obj = api.request("GET", f"/v1/{endpoint}/{resource['id']}", SAFE_FIELDS[resource["kind"]])
            require(status in {200, 403, 404}, f"MANAGED_RELEASE_HTTP_{status}")
            if status == 200:
                verify_resource(obj, resource, control)
                continue
            if parents_absent[parent_id]:
                released += 1  # 403 = project release, not global deletion.
        if released == len(managed) and not any(observed.values()):
            return observed, released
        require(time.monotonic() < end, "MANAGED_CHILD_RELEASE_NOT_CONFIRMED")
        time.sleep(5)  # Reads only; API independently enforces the 20-minute/window bounds.


def run(api, control: dict, ledger: dict, execute: bool = False) -> dict:
    observed, objects = inspect(api, control, ledger)
    if not execute:
        return {"result": "PASS", "mode": "READ_ONLY", "mutations": 0, "enrolled": len(ledger["resources"]), "protection_armed": False}
    require(control.get("allow_exact_cleanup") is True, "CLEANUP_NOT_AUTHORIZED")
    deleted, failures = 0, []
    # Save verified ancillary ownership before server deletion; never discover
    # a new deletable ID during cleanup. Each DELETE is submitted once only.
    for kind in ("server", "backup_storage", "ip"):
        for resource in ledger["resources"]:
            if resource["kind"] != kind or (kind, resource["id"]) not in objects:
                continue
            path = f"/v1/{ENDPOINTS[kind]}/{resource['id']}"
            try:
                status, current = api.request("GET", path, SAFE_FIELDS[kind])
                if status == 404:
                    continue  # provider cascade; final inventory must also be empty
                require(status == 200, f"HTTP_{status}")
                verify_resource(current, resource, control)
                status, _ = api.request("DELETE", path)
                require(status == 204, f"DELETE_HTTP_{status}")
                deleted += 1
                for attempt in range(10):
                    absent, _ = api.request("GET", path, SAFE_FIELDS[kind])
                    if absent == 404:
                        break
                    require(absent == 200, f"ABSENCE_HTTP_{absent}")
                    require(attempt < 9, "DELETION_NOT_CONFIRMED")
                    time.sleep(5)
            except GuardError as error:
                # Never repeat a possibly successful mutation. Continue only
                # with separately enrolled and independently verified IDs.
                failures.append(str(error))
    released = 0
    if any(r["kind"] in MANAGED for r in ledger["resources"]):
        try:
            final, released = await_managed_release(api, control, ledger)
        except GuardError as error:
            failures.append(str(error))
            final = inventory(api, control)
    else:
        final = inventory(api, control)
    if failures or any(final.values()):
        return {"result": "FAIL", "mode": "EXACT_CLEANUP", "reason": "CLEANUP_INCOMPLETE",
                "delete_requests": deleted, "failure_codes": failures,
                "remaining_resources": sum(len(items) for items in final.values())}
    return {"result": "PASS", "mode": "EXACT_CLEANUP", "delete_requests": deleted, "final_inventory_empty": True,
            "provider_managed_children_released_from_project": released,
            "global_provider_record_deletion_claimed": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--probe", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.probe and not args.execute:
        print(json.dumps({"result": "INERT", "mutations": 0}))
        return 0
    try:
        control = parse_json(os.environ.get("NEXSIGHT_CHERRY_CONTROL_JSON", ""))
        ledger = validate(control, os.environ.get("NEXSIGHT_CHERRY_LEDGER_JSON", ""), datetime.now(timezone.utc))
        deadline = utc(control["authorization_expires_utc"])
        if control.get("deletion_deadline_utc"):
            deadline = min(deadline, utc(control["deletion_deadline_utc"]))
        result = run(Api(os.environ.get("CHERRY_API_TOKEN", ""), deadline), control, ledger, execute=args.execute)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["result"] == "PASS" else 2
    except GuardError as error:
        print(json.dumps({"result": "FAIL", "reason": str(error)}, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps({"result": "FAIL", "reason": "INTERNAL_FAILURE"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
