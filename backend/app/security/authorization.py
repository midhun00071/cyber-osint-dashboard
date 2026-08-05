"""Fail-closed helpers for the explicit permission matrix."""

from app.security.contracts import Permission, ROLE_PERMISSIONS, RoleKey


class InvalidRoleError(ValueError):
    pass


def parse_role(role_key: object) -> RoleKey:
    if not isinstance(role_key, str):
        raise InvalidRoleError("Role information is invalid.")
    try:
        return RoleKey(role_key)
    except ValueError:
        raise InvalidRoleError("Role information is invalid.") from None


def permissions_for_role(role: RoleKey) -> frozenset[Permission]:
    permissions = ROLE_PERMISSIONS.get(role)
    if permissions is None:
        raise InvalidRoleError("Role information is invalid.")
    return permissions
