import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings


def make_settings(**values: object) -> Settings:
    get_settings.cache_clear()
    return Settings(_env_file=None, **values)


def test_single_https_origin_is_accepted() -> None:
    settings = make_settings(
        BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.com"
    )

    assert settings.cors_origins_list == ["https://dashboard.example.com"]


def test_multiple_origins_trim_whitespace_and_preserve_order() -> None:
    settings = make_settings(
        BACKEND_CORS_ALLOWED_ORIGINS=(
            " http://localhost:3000, http://127.0.0.1:3000, "
            "https://dashboard.example.com "
        )
    )

    assert settings.cors_origins_list == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://dashboard.example.com",
    ]


def test_surrounding_ascii_spaces_are_trimmed() -> None:
    settings = make_settings(
        BACKEND_CORS_ALLOWED_ORIGINS="   https://dashboard.example.com   "
    )

    assert settings.cors_origins_list == ["https://dashboard.example.com"]


def test_development_defaults_include_only_known_frontend_origins() -> None:
    settings = make_settings()

    assert settings.cors_origins_list == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    assert "*" not in settings.cors_origins_list


def test_duplicate_origins_are_normalized_deterministically() -> None:
    settings = make_settings(
        BACKEND_CORS_ALLOWED_ORIGINS=(
            "https://Dashboard.Example.com,https://dashboard.example.com"
        )
    )

    assert settings.cors_origins_list == ["https://dashboard.example.com"]


@pytest.mark.parametrize(
    "configured_origin",
    [
        "https://dash\tboard.example.com",
        "https://dashboard.example.com\n.evil.test",
        "https://dashboard.example.com\r.evil.test",
        "https://dashboard.example.com\x00.evil.test",
        "https://dashboard.example.com\x85.evil.test",
        "https://dashboard.example.com\u200b.evil.test",
    ],
)
def test_control_format_and_nonprintable_characters_are_rejected_before_parsing(
    configured_origin: str,
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        make_settings(BACKEND_CORS_ALLOWED_ORIGINS=configured_origin)

    message = str(exc_info.value)
    assert "BACKEND_CORS_ALLOWED_ORIGINS" in message
    assert configured_origin not in message
    assert "DATABASE_URL" not in message
    assert "POSTGRES_PASSWORD" not in message


@pytest.mark.parametrize(
    "configured_origins",
    [
        "*",
        "https://*.example.com",
        "",
        "   ",
        "https://dashboard.example.com,",
        ",https://dashboard.example.com",
        "https://dashboard.example.com/path",
        "https://dashboard.example.com?mode=test",
        "https://dashboard.example.com#fragment",
        "https://user@dashboard.example.com",
        "https://user:password@dashboard.example.com",
        "ftp://dashboard.example.com",
        "https://dashboard.example.com:not-a-port",
        "https://dashboard.example.com:",
        "https://dashboard.example.com:0",
    ],
)
def test_invalid_or_non_origin_configuration_is_rejected(
    configured_origins: str,
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        make_settings(BACKEND_CORS_ALLOWED_ORIGINS=configured_origins)

    message = str(exc_info.value)
    assert "BACKEND_CORS_ALLOWED_ORIGINS" in message
    assert "DATABASE_URL" not in message
    assert "POSTGRES_PASSWORD" not in message


def test_production_requires_explicit_non_loopback_https_origins() -> None:
    with pytest.raises(ValidationError, match="non-loopback HTTPS origins"):
        make_settings(APP_ENV="production")

    with pytest.raises(ValidationError, match="non-loopback HTTPS origins"):
        make_settings(
            APP_ENV="production",
            BACKEND_CORS_ALLOWED_ORIGINS="http://dashboard.example.com",
        )


@pytest.mark.parametrize(
    "loopback_origin",
    [
        "https://localhost:3000",
        "https://foo.localhost:3000",
        "https://127.0.0.1:3000",
        "https://127.0.0.2:3000",
        "https://[::1]:3000",
    ],
)
def test_production_rejects_loopback_origins(loopback_origin: str) -> None:
    with pytest.raises(ValidationError, match="non-loopback HTTPS origins"):
        make_settings(
            APP_ENV="production",
            BACKEND_CORS_ALLOWED_ORIGINS=loopback_origin,
        )


def test_development_accepts_known_loopback_origins() -> None:
    settings = make_settings(
        APP_ENV="development",
        BACKEND_CORS_ALLOWED_ORIGINS=(
            "http://localhost:3000,http://127.0.0.1:3000,http://[::1]:3000"
        ),
    )

    assert settings.cors_origins_list == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
    ]


def test_production_accepts_an_explicit_https_allow_list() -> None:
    settings = make_settings(
        APP_ENV="production",
        BACKEND_CORS_ALLOWED_ORIGINS="https://dashboard.example.com",
    )

    assert settings.cors_origins_list == ["https://dashboard.example.com"]


def test_production_does_not_reject_non_loopback_private_ip_origins() -> None:
    settings = make_settings(
        APP_ENV="production",
        BACKEND_CORS_ALLOWED_ORIGINS="https://10.0.0.5:8443",
    )

    assert settings.cors_origins_list == ["https://10.0.0.5:8443"]


@pytest.mark.parametrize(
    ("configured_origin", "expected_origin"),
    [
        ("http://dashboard.example.com:80", "http://dashboard.example.com"),
        ("https://dashboard.example.com:443", "https://dashboard.example.com"),
        ("https://dashboard.example.com:8443", "https://dashboard.example.com:8443"),
        ("http://[0:0:0:0:0:0:0:1]:3000", "http://[::1]:3000"),
    ],
)
def test_origins_use_browser_default_port_and_canonical_ip_representation(
    configured_origin: str,
    expected_origin: str,
) -> None:
    settings = make_settings(BACKEND_CORS_ALLOWED_ORIGINS=configured_origin)

    assert settings.cors_origins_list == [expected_origin]


def test_equivalent_default_port_origins_deduplicate() -> None:
    settings = make_settings(
        BACKEND_CORS_ALLOWED_ORIGINS=(
            "http://dashboard.example.com:80,http://dashboard.example.com,"
            "https://dashboard.example.com:443,https://dashboard.example.com"
        )
    )

    assert settings.cors_origins_list == [
        "http://dashboard.example.com",
        "https://dashboard.example.com",
    ]
