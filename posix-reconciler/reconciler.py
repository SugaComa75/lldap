#!/usr/bin/env python3
"""Keep LLDAP's RFC2307 attributes in sync for NAS LDAP clients.

The service talks only to LLDAP's documented HTTP/GraphQL API.  It never
changes an existing POSIX identity value unless memberUid is derived from the
canonical LLDAP group membership and needs refreshing.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


USER_SCHEMA = {
    "uidnumber": ("INTEGER", False),
    "gidnumber": ("INTEGER", False),
    "homedirectory": ("STRING", False),
    "loginshell": ("STRING", False),
    "unixshell": ("STRING", False),
    "gecos": ("STRING", False),
}
GROUP_SCHEMA = {
    "gidnumber": ("INTEGER", False),
    "memberuid": ("STRING", True),
}

INVENTORY_QUERY = """
query PosixInventory {
  users {
    id displayName firstName lastName
    attributes { name value }
  }
  groups {
    id displayName
    users { id }
    attributes { name value }
  }
  schema {
    userSchema {
      attributes { name attributeType isList }
      ldapObjectClasses { objectClass }
      extraLdapObjectClasses
    }
    groupSchema {
      attributes { name attributeType isList }
      ldapObjectClasses { objectClass }
      extraLdapObjectClasses
    }
  }
}
"""

UPDATE_USER = """
mutation PosixUpdateUser($user: UpdateUserInput!) {
  updateUser(user: $user) { ok }
}
"""
UPDATE_GROUP = """
mutation PosixUpdateGroup($group: UpdateGroupInput!) {
  updateGroup(group: $group) { ok }
}
"""


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def attributes_by_name(item: dict[str, Any]) -> dict[str, list[str]]:
    return {
        attr["name"].lower(): [str(value) for value in attr.get("value", [])]
        for attr in item.get("attributes", [])
    }


def first_value(attributes: dict[str, list[str]], name: str) -> str | None:
    values = attributes.get(name.lower(), [])
    return values[0].strip() if values and values[0].strip() else None


def clean_gecos(user: dict[str, Any]) -> str:
    display_name = (user.get("displayName") or "").strip()
    if display_name:
        return display_name
    full_name = " ".join(
        part.strip()
        for part in (user.get("firstName") or "", user.get("lastName") or "")
        if part.strip()
    )
    return full_name or user["id"]


@dataclass
class Settings:
    base_url: str
    username: str
    password: str
    dry_run: bool = True
    verify_tls: bool = True
    uid_start: int = 10000
    gid_start: int = 10000
    default_gid: int | None = None
    primary_group: str = "lldap_users"
    excluded_users: frozenset[str] = frozenset()
    home_root: str = "/home"
    login_shell: str = "/bin/sh"
    interval_seconds: int = 300
    run_once: bool = False
    state_path: Path = Path("/state/allocator.json")

    @classmethod
    def from_env(cls) -> "Settings":
        password = os.getenv("LLDAP_ADMIN_PASSWORD", "")
        password_file = os.getenv("LLDAP_ADMIN_PASSWORD_FILE", "")
        if not password and password_file:
            password = Path(password_file).read_text(encoding="utf-8").strip()
        return cls(
            base_url=os.getenv("LLDAP_URL", "http://lldap:17170").rstrip("/"),
            username=os.getenv("LLDAP_ADMIN_USERNAME", "admin"),
            password=password,
            dry_run=env_bool("POSIX_DRY_RUN", True),
            verify_tls=env_bool("LLDAP_VERIFY_TLS", True),
            uid_start=int(os.getenv("POSIX_UID_START", "10000")),
            gid_start=int(os.getenv("POSIX_GID_START", "10000")),
            default_gid=(int(os.environ["POSIX_DEFAULT_GID"]) if os.getenv("POSIX_DEFAULT_GID", "").strip() else None),
            primary_group=os.getenv("POSIX_PRIMARY_GROUP", "lldap_users").strip(),
            excluded_users=frozenset(
                value.strip().lower()
                for value in os.getenv("POSIX_EXCLUDE_USERS", "").split(",")
                if value.strip()
            ),
            home_root=os.getenv("POSIX_HOME_ROOT", "/home").rstrip("/"),
            login_shell=os.getenv("POSIX_LOGIN_SHELL", "/bin/sh"),
            interval_seconds=max(10, int(os.getenv("POSIX_INTERVAL_SECONDS", "300"))),
            run_once=env_bool("POSIX_RUN_ONCE", False),
            state_path=Path(os.getenv("POSIX_STATE_PATH", "/state/allocator.json")),
        )


class LldapClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.token = ""
        self.ssl_context = ssl.create_default_context()
        if not settings.verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def post(self, path: str, payload: dict[str, Any], authenticated: bool = True) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            self.settings.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, context=self.ssl_context, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLDAP HTTP {error.code}: {body[:500]}") from error

    def login(self) -> None:
        if not self.settings.password:
            raise RuntimeError("LLDAP_ADMIN_PASSWORD or LLDAP_ADMIN_PASSWORD_FILE is required")
        result = self.post(
            "/auth/simple/login",
            {"username": self.settings.username, "password": self.settings.password},
            authenticated=False,
        )
        self.token = result["token"]

    def graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self.post("/api/graphql", {"query": query, "variables": variables or {}})
        if result.get("errors"):
            raise RuntimeError("LLDAP GraphQL error: " + json.dumps(result["errors"]))
        return result["data"]


def load_state(path: Path, uid_start: int, gid_start: int) -> dict[str, int]:
    state = {"next_uid": uid_start, "next_gid": gid_start}
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
        state["next_uid"] = max(uid_start, int(stored.get("next_uid", uid_start)))
        state["next_gid"] = max(gid_start, int(stored.get("next_gid", gid_start)))
    except FileNotFoundError:
        pass
    return state


def save_state(path: Path, state: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def advance_high_water(state: dict[str, int], users: list[dict[str, Any]], groups: list[dict[str, Any]]) -> None:
    for user in users:
        value = first_value(attributes_by_name(user), "uidnumber")
        if value and value.isdigit():
            state["next_uid"] = max(state["next_uid"], int(value) + 1)
    for group in groups:
        value = first_value(attributes_by_name(group), "gidnumber")
        if value and value.isdigit():
            state["next_gid"] = max(state["next_gid"], int(value) + 1)


def plan_user(
    user: dict[str, Any], uid_number: int, settings: Settings, primary_gid: int | None
) -> dict[str, Any]:
    attrs = attributes_by_name(user)
    desired = {
        "uidnumber": str(uid_number),
        "homedirectory": f"{settings.home_root}/{user['id']}",
        "loginshell": settings.login_shell,
        "unixshell": settings.login_shell,
        "gecos": clean_gecos(user),
    }
    if primary_gid is not None:
        desired["gidnumber"] = str(primary_gid)
    return {
        "id": user["id"],
        "_displayName": user.get("displayName") or user["id"],
        "insertAttributes": [
            {"name": name, "value": [value]}
            for name, value in desired.items()
            if not first_value(attrs, name)
        ],
    }


def plan_group(group: dict[str, Any], gid_number: int) -> dict[str, Any]:
    attrs = attributes_by_name(group)
    insertions: list[dict[str, Any]] = []
    if not first_value(attrs, "gidnumber"):
        insertions.append({"name": "gidnumber", "value": [str(gid_number)]})
    canonical_members = sorted({user["id"] for user in group.get("users", [])})
    current_members = sorted(set(attrs.get("memberuid", [])))
    removals: list[str] = []
    if canonical_members != current_members:
        if canonical_members:
            insertions.append({"name": "memberuid", "value": canonical_members})
        elif current_members:
            removals.append("memberuid")
    change: dict[str, Any] = {
        "id": group["id"],
        "_displayName": group["displayName"],
        "insertAttributes": insertions,
    }
    if removals:
        change["removeAttributes"] = removals
    return change


def schema_actions(schema: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for side, required, object_class in (
        ("user", USER_SCHEMA, "posixAccount"),
        ("group", GROUP_SCHEMA, "posixGroup"),
    ):
        current = schema[f"{side}Schema"]
        attributes = {item["name"].lower() for item in current["attributes"]}
        classes = {
            item["objectClass"].lower() for item in current["ldapObjectClasses"]
        } | {name.lower() for name in current.get("extraLdapObjectClasses", [])}
        for name, (kind, is_list) in required.items():
            if name not in attributes:
                actions.append({"kind": "attribute", "side": side, "name": name, "type": kind, "list": is_list})
        if object_class.lower() not in classes:
            actions.append({"kind": "object_class", "side": side, "name": object_class})
    return actions


def apply_schema_action(client: LldapClient, action: dict[str, Any]) -> None:
    if action["kind"] == "object_class":
        field = "addUserObjectClass" if action["side"] == "user" else "addGroupObjectClass"
        query = f'mutation {{ {field}(name: {json.dumps(action["name"])}) {{ ok }} }}'
    else:
        field = "addUserAttribute" if action["side"] == "user" else "addGroupAttribute"
        query = (
            f'mutation {{ {field}(name: {json.dumps(action["name"])}, '
            f'attributeType: {action["type"]}, isList: {str(action["list"]).lower()}, '
            'isVisible: true, isEditable: false) { ok } }'
        )
    client.graphql(query)


def reconcile(client: LldapClient, settings: Settings) -> dict[str, Any]:
    inventory = client.graphql(INVENTORY_QUERY)
    users = sorted(inventory["users"], key=lambda item: item["id"])
    groups = sorted(inventory["groups"], key=lambda item: (item["displayName"].lower(), item["id"]))
    state = load_state(settings.state_path, settings.uid_start, settings.gid_start)
    advance_high_water(state, users, groups)

    schema_plan = schema_actions(inventory["schema"])
    group_plan: list[dict[str, Any]] = []
    group_gids: dict[str, int] = {}
    for group in groups:
        attrs = attributes_by_name(group)
        allocation = int(first_value(attrs, "gidnumber") or state["next_gid"])
        group_gids[group["displayName"].lower()] = allocation
        change = plan_group(group, allocation)
        if change["insertAttributes"] or change.get("removeAttributes"):
            group_plan.append(change)
        if not first_value(attrs, "gidnumber"):
            state["next_gid"] += 1

    warnings: list[str] = []
    primary_gid = settings.default_gid
    if primary_gid is None and settings.primary_group:
        primary_gid = group_gids.get(settings.primary_group.lower())
    if primary_gid is None:
        warnings.append(
            "No primary GID selected; set POSIX_PRIMARY_GROUP to an existing LLDAP group "
            "or set POSIX_DEFAULT_GID explicitly. Missing user gidNumber values were not changed."
        )

    user_plan: list[dict[str, Any]] = []
    for user in users:
        if user["id"].lower() in settings.excluded_users:
            continue
        attrs = attributes_by_name(user)
        allocation = int(first_value(attrs, "uidnumber") or state["next_uid"])
        change = plan_user(user, allocation, settings, primary_gid)
        if change["insertAttributes"]:
            user_plan.append(change)
        if not first_value(attrs, "uidnumber"):
            state["next_uid"] += 1

    report = {
        "dryRun": settings.dry_run,
        "schemaActions": schema_plan,
        "userUpdates": user_plan,
        "groupUpdates": group_plan,
        "selectedPrimaryGid": primary_gid,
        "warnings": warnings,
        "excludedUsers": sorted(settings.excluded_users),
        "groupInventory": [
            {
                "id": group["id"],
                "name": group["displayName"],
                "gidNumber": group_gids[group["displayName"].lower()],
                "members": sorted(user["id"] for user in group.get("users", [])),
            }
            for group in groups
        ],
        "nextIds": state,
    }
    if settings.dry_run:
        return report

    for action in schema_plan:
        apply_schema_action(client, action)
    for user in user_plan:
        client.graphql(UPDATE_USER, {"user": {key: value for key, value in user.items() if not key.startswith("_")}})
    for group in group_plan:
        client.graphql(UPDATE_GROUP, {"group": {key: value for key, value in group.items() if not key.startswith("_")}})
    save_state(settings.state_path, state)
    return report


def main() -> int:
    settings = Settings.from_env()
    while True:
        try:
            client = LldapClient(settings)
            client.login()
            report = reconcile(client, settings)
            print(json.dumps(report, separators=(",", ":")), flush=True)
        except Exception as error:
            print(json.dumps({"level": "error", "message": str(error)}), file=sys.stderr, flush=True)
            if settings.run_once:
                return 1
        if settings.run_once:
            return 0
        time.sleep(settings.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
