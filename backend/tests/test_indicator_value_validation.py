import socket

import pytest

from app.indicators.value_normalization import (
    IndicatorValueError,
    MAX_CANONICAL_URL_LENGTH,
    normalize_observable,
)


def test_ipv4_normalization_accepts_valid_metadata_and_rejects_invalid_syntax():
    result = normalize_observable("ipv4", " 192.0.2.10 ")

    assert result.observable_type == "ipv4"
    assert result.normalized_value == "192.0.2.10"
    assert result.hash_algorithm is None

    for value in ("999.1.1.1", "192.0.2.1/24", "192.0.2.1:443", ""):
        with pytest.raises(IndicatorValueError, match="IP address"):
            normalize_observable("ipv4", value)


def test_ipv6_normalization_returns_canonical_compressed_text():
    result = normalize_observable(
        "ipv6",
        "2001:0DB8:0000:0000:0000:FF00:0042:8329",
    )

    assert result.normalized_value == "2001:db8::ff00:42:8329"

    with pytest.raises(IndicatorValueError, match="version"):
        normalize_observable("ipv6", "192.0.2.10")
    with pytest.raises(IndicatorValueError, match="syntax"):
        normalize_observable("ipv6", "fe80::1%eth0")


@pytest.mark.parametrize(
    ("observable_type", "value"),
    [
        ("ipv4", "192.0.2.10\u0085"),
        ("ipv4", "\u0085192.0.2.10"),
        ("ipv4", "192.0.\n2.10"),
        ("ipv4", "192.0.\t2.10"),
        ("ipv6", "2001:db8::1\u0085"),
        ("ipv6", "\u00852001:db8::1"),
        ("ipv6", "2001:db8::\n1"),
        ("ipv6", "2001:db8::\t1"),
    ],
)
def test_ip_normalization_rejects_literal_controls_before_trimming(
    observable_type,
    value,
):
    with pytest.raises(IndicatorValueError) as exc_info:
        normalize_observable(observable_type, value)

    assert value not in str(exc_info.value)


def test_domain_normalization_handles_case_root_dot_and_idna():
    assert normalize_observable("domain", " Example.COM. ").normalized_value == (
        "example.com"
    )
    assert normalize_observable("domain", "täst.de").normalized_value == (
        "xn--tst-qla.de"
    )
    assert normalize_observable("domain", "example.com\u3002").normalized_value == (
        "example.com"
    )


def test_non_transitional_idna_preserves_sharp_s_identity_distinction():
    sharp_s = normalize_observable("domain", "faß.de")
    ascii_ss = normalize_observable("domain", "fass.de")

    assert sharp_s.normalized_value == "xn--fa-hia.de"
    assert ascii_ss.normalized_value == "fass.de"
    assert sharp_s.identity_sha256 != ascii_ss.identity_sha256

    sharp_s_url = normalize_observable("url", "https://faß.de")
    ascii_ss_url = normalize_observable("url", "https://fass.de")

    assert sharp_s_url.normalized_value == "https://xn--fa-hia.de/"
    assert ascii_ss_url.normalized_value == "https://fass.de/"
    assert sharp_s_url.identity_sha256 != ascii_ss_url.identity_sha256


@pytest.mark.parametrize(
    "value",
    [
        "singlelabel",
        "bad label.example",
        "*.example.com",
        "https://example.com",
        "example.com/path",
        "user@example.com",
        "bad..example.com",
        "-bad.example.com",
        "xn--a.com",
        f"{'a' * 64}.example.com",
        "example.com\nignored.invalid",
    ],
)
def test_domain_normalization_rejects_unsafe_or_invalid_hostnames(value):
    with pytest.raises(IndicatorValueError, match="Domain syntax is invalid"):
        normalize_observable("domain", value)


@pytest.mark.parametrize(
    "value",
    [
        "\u0085example.com",
        "example.com\u0085",
        "exam\u0080ple.com",
    ],
)
def test_domain_normalization_rejects_literal_unicode_controls_before_trimming(
    value,
):
    with pytest.raises(IndicatorValueError) as exc_info:
        normalize_observable("domain", value)

    assert value not in str(exc_info.value)


def test_domain_normalization_still_trims_spaces_and_accepts_idna_letters():
    assert normalize_observable("domain", "  faß.de  ").normalized_value == (
        "xn--fa-hia.de"
    )


def test_url_normalization_handles_http_https_ports_idna_and_fragments():
    assert normalize_observable(
        "url",
        "HTTP://Example.COM:80/path?q=One#section",
    ).normalized_value == "http://example.com/path?q=One"
    assert normalize_observable(
        "url",
        "HTTPS://TÄST.DE:443/a%20b?x=1#fragment",
    ).normalized_value == "https://xn--tst-qla.de/a%20b?x=1"
    assert normalize_observable(
        "url",
        "https://example.com:8443/path",
    ).normalized_value == "https://example.com:8443/path"
    assert normalize_observable(
        "url",
        "https://[2001:0db8::1]/path",
    ).normalized_value == "https://[2001:db8::1]/path"
    assert normalize_observable(
        "url",
        "http://192.0.2.10",
    ).normalized_value == "http://192.0.2.10/"


def test_url_root_path_query_and_percent_escape_case_are_canonical():
    without_slash = normalize_observable("url", "http://example.com")
    with_slash = normalize_observable("url", "http://example.com/")

    assert without_slash.normalized_value == "http://example.com/"
    assert without_slash == with_slash

    query_without_slash = normalize_observable("url", "https://example.com?x=%7e")
    query_with_slash = normalize_observable("url", "https://example.com/?x=%7E")

    assert query_without_slash.normalized_value == "https://example.com/?x=%7E"
    assert query_without_slash == query_with_slash

    lower_escape = normalize_observable("url", "https://example.com/%7euser?q=%2f")
    upper_escape = normalize_observable("url", "https://example.com/%7Euser?q=%2F")

    assert lower_escape.normalized_value == "https://example.com/%7Euser?q=%2F"
    assert lower_escape == upper_escape


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com/file",
        "https:///missing-host",
        "https://user:password@example.com/path",
        "https://example.com:not-a-port/path",
        "https://example.com:65536/path",
        "https://example.com:0/path",
        "https://example.com:",
        "https://example.com:/path",
        "https://[2001:db8::1]:",
        "https://example.com/bad path",
        "https://example.com/bad%escape",
        "https://example.com\\path",
    ],
)
def test_url_normalization_rejects_unsupported_or_ambiguous_values(value):
    with pytest.raises(IndicatorValueError):
        normalize_observable("url", value)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/path\u0080segment",
        "https://example.com/?query=value\u009f",
        "\u0085https://example.com/",
        "https://example.com/\u0085",
        "https://example.com/line\nbreak",
        "https://example.com/tab\tvalue",
    ],
)
def test_url_normalization_rejects_literal_unicode_controls_before_trimming(value):
    with pytest.raises(IndicatorValueError) as exc_info:
        normalize_observable("url", value)

    assert value not in str(exc_info.value)


def test_url_normalization_trims_spaces_without_decoding_percent_escapes():
    result = normalize_observable(
        "url",
        "  https://example.com/%00?q=%7e  ",
    )

    assert result.normalized_value == "https://example.com/%00?q=%7E"


def test_url_normalization_enforces_canonical_length_bound():
    allowed = "https://example.com/" + "a" * (
        MAX_CANONICAL_URL_LENGTH - len("https://example.com/")
    )
    assert len(normalize_observable("url", allowed).normalized_value) == (
        MAX_CANONICAL_URL_LENGTH
    )

    with pytest.raises(IndicatorValueError, match="allowed length"):
        normalize_observable("url", allowed + "a")


@pytest.mark.parametrize(
    ("algorithm", "length"),
    [("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128)],
)
def test_file_hash_normalization_accepts_supported_exact_hex_metadata(
    algorithm,
    length,
):
    result = normalize_observable(
        "file_hash",
        "A" * length,
        hash_algorithm=algorithm.upper(),
    )

    assert result.normalized_value == "a" * length
    assert result.hash_algorithm == algorithm


@pytest.mark.parametrize(
    ("algorithm", "value"),
    [
        ("md5", "a" * 31),
        ("sha1", "g" * 40),
        ("sha256", "sha256:" + "a" * 64),
        ("sha512", "a" * 64 + "-" + "a" * 63),
        ("md5", " a" * 16),
    ],
)
def test_file_hash_normalization_rejects_wrong_length_or_non_hex(
    algorithm,
    value,
):
    with pytest.raises(IndicatorValueError, match="File-hash"):
        normalize_observable("file_hash", value, hash_algorithm=algorithm)


def test_hash_algorithm_is_required_only_for_file_hashes():
    with pytest.raises(IndicatorValueError, match="required"):
        normalize_observable("file_hash", "a" * 32)
    with pytest.raises(IndicatorValueError, match="only valid"):
        normalize_observable("domain", "example.com", hash_algorithm="md5")
    with pytest.raises(IndicatorValueError, match="not supported"):
        normalize_observable(
            "file_hash",
            "a" * 64,
            hash_algorithm="sha3",
        )


def test_identity_fingerprint_is_deterministic_separated_and_lowercase_hex():
    first = normalize_observable("domain", "EXAMPLE.com.")
    equivalent = normalize_observable(" DOMAIN ", "example.com")
    different = normalize_observable("url", "https://example.com")

    assert first.identity_sha256 == equivalent.identity_sha256
    assert first.identity_sha256 != different.identity_sha256
    assert len(first.identity_sha256) == 64
    assert set(first.identity_sha256) <= set("0123456789abcdef")


def test_validation_is_strictly_offline(monkeypatch):
    def fail_network(*args, **kwargs):
        pytest.fail("observable normalization must not access the network")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    monkeypatch.setattr(socket, "getaddrinfo", fail_network)

    assert normalize_observable("ipv4", "198.51.100.4").normalized_value
    assert normalize_observable("domain", "example.com").normalized_value
    assert normalize_observable("url", "https://example.com/path").normalized_value


def test_validation_errors_do_not_echo_attacker_controlled_values():
    unsafe_value = "user:synthetic-sensitive-value@example.com"

    with pytest.raises(IndicatorValueError) as exc_info:
        normalize_observable("domain", unsafe_value)

    assert unsafe_value not in str(exc_info.value)
