"""Allow-listed administrator user-management schemas."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.security.contracts import RoleKey


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class CreateAdminUserRequest(_StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_.-]{2,63}$")
    display_name: str = Field(min_length=1, max_length=160, pattern=r"^\S(?:.*\S)?$")
    password: SecretStr = Field(min_length=12, max_length=128)
    role: RoleKey
    account_expires_at: datetime | None = None

    @field_validator("account_expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Account expiry must include a timezone.")
        return value


class UserStatusRequest(_StrictModel):
    status: Literal["active", "disabled"]


class UserRoleRequest(_StrictModel):
    role: RoleKey


class UserExpiryRequest(_StrictModel):
    account_expires_at: datetime | None

    _require_aware_expiry = field_validator("account_expires_at")(CreateAdminUserRequest.require_aware_expiry.__func__)


class AdminUserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
    public_id: UUID
    username: str
    display_name: str
    status: Literal["active", "disabled"]
    role: RoleKey
    permissions: list[str]
    account_expires_at: datetime | None
    last_authenticated_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AdminUserListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[AdminUserResponse]
    total: int
    limit: int
    offset: int
