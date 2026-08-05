"""Bounded Argon2id password hashing with one-process dummy verification data."""

from __future__ import annotations

import unicodedata

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


MIN_PASSWORD_CHARACTERS = 12
MAX_PASSWORD_CHARACTERS = 128
MAX_PASSWORD_UTF8_BYTES = 512
SAFE_PASSWORD_ERROR = "The password could not be accepted."

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash("dummy-verification-only-password")


class PasswordPolicyError(ValueError):
    """Fixed password-policy failure that never contains submitted data."""


def validate_password(password: object) -> str:
    if not isinstance(password, str):
        raise PasswordPolicyError(SAFE_PASSWORD_ERROR)
    if not MIN_PASSWORD_CHARACTERS <= len(password) <= MAX_PASSWORD_CHARACTERS:
        raise PasswordPolicyError(SAFE_PASSWORD_ERROR)
    try:
        encoded = password.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise PasswordPolicyError(SAFE_PASSWORD_ERROR) from None
    if not encoded or len(encoded) > MAX_PASSWORD_UTF8_BYTES:
        raise PasswordPolicyError(SAFE_PASSWORD_ERROR)
    if "\x00" in password or any(unicodedata.category(character) == "Cc" for character in password):
        raise PasswordPolicyError(SAFE_PASSWORD_ERROR)
    return password


def hash_password(password: object) -> str:
    encoded = _PASSWORD_HASHER.hash(validate_password(password))
    if not encoded.startswith("$argon2id$"):
        raise RuntimeError("Password hashing failed safely.")
    return encoded


def verify_password(password: object, encoded_hash: str | None) -> bool:
    candidate = password if isinstance(password, str) else ""
    verification_hash = encoded_hash if isinstance(encoded_hash, str) else _DUMMY_PASSWORD_HASH
    try:
        return bool(_PASSWORD_HASHER.verify(verification_hash, candidate))
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError):
        return False


def dummy_password_hash() -> str:
    return _DUMMY_PASSWORD_HASH


def password_hash_needs_rehash(encoded_hash: str) -> bool:
    try:
        return _PASSWORD_HASHER.check_needs_rehash(encoded_hash)
    except (InvalidHashError, TypeError):
        return False
