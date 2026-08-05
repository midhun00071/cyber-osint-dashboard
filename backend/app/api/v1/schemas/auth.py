"""Strict authentication request and safe principal response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.security.contracts import RoleKey


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_.-]{2,63}$")
    password: SecretStr = Field(min_length=12, max_length=128)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    current_password: SecretStr = Field(min_length=12, max_length=128)
    new_password: SecretStr = Field(min_length=12, max_length=128)


class PrincipalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
    public_id: UUID
    display_name: str
    role: RoleKey
    permissions: list[str]
    account_expires_at: datetime | None
