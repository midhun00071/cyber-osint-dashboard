import pytest

from app.security.passwords import MAX_PASSWORD_CHARACTERS, PasswordPolicyError, dummy_password_hash, hash_password, password_hash_needs_rehash, validate_password, verify_password


def test_argon2id_hash_and_verification() -> None:
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("$argon2id$")
    assert verify_password("correct horse battery staple", encoded) is True
    assert verify_password("wrong password value", encoded) is False
    assert password_hash_needs_rehash(encoded) is False


@pytest.mark.parametrize("value", ["short", "valid-password\x00", "valid-password\n", "x" * (MAX_PASSWORD_CHARACTERS + 1)])
def test_password_policy_rejects_unsafe_values_without_echo(value: str) -> None:
    with pytest.raises(PasswordPolicyError) as error:
        validate_password(value)
    assert value not in str(error.value)


def test_dummy_hash_is_one_argon2id_process_value() -> None:
    assert dummy_password_hash().startswith("$argon2id$")
    assert dummy_password_hash() == dummy_password_hash()
