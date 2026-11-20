"""Case-level access control.

Platform roles (auth.users.role): ``admin`` or ``officer``.
Case roles (database.case_members.case_role):

=================  ======  ============  ======  =====
permission         viewer  investigator  lead    admin
=================  ======  ============  ======  =====
view               yes     yes           yes     yes
edit (upload, chat, leads, notes, reports, custody)
                   no      yes           yes     yes
manage (delete evidence/case, members)
                   no      no            yes     yes
=================  ======  ============  ======  =====

Officers only see cases they are members of. Admins see every case.
"""

from __future__ import annotations

from typing import Any

from modules import database

PERMISSIONS = {
    "view": {"viewer", "investigator", "lead"},
    "edit": {"investigator", "lead"},
    "manage": {"lead"},
}


class AccessDenied(PermissionError):
    pass


def is_admin(user: dict[str, Any]) -> bool:
    return bool(user) and user.get("role") == "admin" and user.get("status") == "approved"


def case_role(user: dict[str, Any], case_id: str) -> str | None:
    if is_admin(user):
        return "admin"
    return database.get_case_role(case_id, user["user_id"])


def can(user: dict[str, Any], case_id: str, permission: str) -> bool:
    if permission not in PERMISSIONS:
        raise ValueError(f"Unknown permission {permission!r}")
    role = case_role(user, case_id)
    return role == "admin" or role in PERMISSIONS[permission]


def require(user: dict[str, Any], case_id: str, permission: str) -> None:
    if not can(user, case_id, permission):
        with database.acting_as(user.get("email")):
            database.log_activity(case_id, "access_denied", {"permission": permission}) \
                if _case_exists(case_id) else None
        raise AccessDenied(f"You do not have '{permission}' permission on case {case_id}.")


def _case_exists(case_id: str) -> bool:
    return any(case["case_id"] == case_id for case in database.list_cases())


def accessible_cases(user: dict[str, Any]) -> list[dict[str, Any]]:
    if is_admin(user):
        return database.list_cases()
    return database.list_cases(user["user_id"], include_all=False)
