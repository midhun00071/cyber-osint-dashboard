from decimal import Decimal
import socket

import httpx
import pytest

from app.indicators.text_extraction import (
    MAX_CONTEXT_SUMMARY_LENGTH,
    MAX_TOTAL_CANDIDATES,
    IOCTextExtractionError,
    extract_iocs,
)


MD5 = "0123456789abcdef" * 2
SHA1 = "0123456789abcdef" * 2 + "01234567"
SHA256 = "0123456789abcdef" * 4
SHA512 = "0123456789abcdef" * 8


def _values(result):
    return [
        (observable.normalized.observable_type, observable.normalized.normalized_value)
        for observable in result.observables
    ]


def test_extracts_supported_literal_and_defanged_observables_in_source_order():
    result = extract_iocs(
        "IOC https://malicious.co/a then hxxps[:]//bad[.]co/path "
        "and IP 8.8.8.8",
        "address 2606:4700:4700::1111; 9[.]9[.]9[.]9; "
        "domain suspicious-domain.co; other[.]co; "
        f"MD5 {MD5}; SHA-1 {SHA1}; SHA256 {SHA256}; SHA-512 {SHA512}",
    )

    assert result.status == "extracted"
    assert _values(result) == [
        ("url", "https://malicious.co/a"),
        ("url", "https://bad.co/path"),
        ("ipv4", "8.8.8.8"),
        ("ipv6", "2606:4700:4700::1111"),
        ("ipv4", "9.9.9.9"),
        ("domain", "suspicious-domain.co"),
        ("domain", "other.co"),
        ("file_hash", MD5),
        ("file_hash", SHA1),
        ("file_hash", SHA256),
        ("file_hash", SHA512),
    ]
    assert {item.source_field for item in result.observables} == {"title", "summary"}
    assert all(len(item.context_summary) <= MAX_CONTEXT_SUMMARY_LENGTH for item in result.observables)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("hxxp://evil[.]co/a", "http://evil.co/a"),
        ("hxxps://evil(.)co/a", "https://evil.co/a"),
        ("http[:]//evil[.]co/a", "http://evil.co/a"),
        ("https[:]//evil(.)co/a", "https://evil.co/a"),
    ],
)
def test_supported_url_defanging_is_narrow_and_normalized(candidate, expected):
    result = extract_iocs(f"IOC URL {candidate}")

    assert _values(result) == [("url", expected)]
    assert result.observables[0].extraction_form == "defanged"


def test_duplicates_keep_first_order_highest_confidence_and_title_tie():
    result = extract_iocs(
        "IOC domain duplicate.co and URL https://tie.co/a",
        "duplicate[.]co then URL https://tie.co/a",
    )

    assert _values(result) == [
        ("domain", "duplicate.co"),
        ("url", "https://tie.co/a"),
    ]
    duplicate, tied = result.observables
    assert duplicate.confidence == Decimal("0.900")
    assert duplicate.extraction_form == "defanged"
    assert duplicate.source_field == "summary"
    assert tied.source_field == "title"


def test_accepted_url_suppresses_overlapping_host_and_ip_candidates():
    result = extract_iocs(
        "IOC URLs https://hosted-malware.co/path and http://8.8.8.8/a"
    )

    assert _values(result) == [
        ("url", "https://hosted-malware.co/path"),
        ("url", "http://8.8.8.8/a"),
    ]


@pytest.mark.parametrize(
    "text",
    [
        "IOC ftp://evil[.]co/a",
        "IOC ftp[:]//evil[.]co/a",
        "IOC javascript[:]//evil[.]co/a",
        "IOC hxxps[:]//user:password@sub[.]evil[.]co/a",
        "IOC hxxps[:]//mixed[.]evil(.)co/a",
    ],
)
def test_rejected_uri_like_tokens_never_fall_back_to_lower_level_observables(text):
    assert extract_iocs(text).observables == ()


@pytest.mark.parametrize(
    ("text", "excluded_urls", "excluded_hosts"),
    [
        ("IOC hxxps[:]//evil[.]co/a", (), ("evil.co",)),
        (
            "IOC hxxps[:]//8[.]8[.]8[.]8/path",
            ("https://8.8.8.8/path",),
            (),
        ),
    ],
)
def test_excluded_defanged_uri_hosts_do_not_fall_back(
    text,
    excluded_urls,
    excluded_hosts,
):
    result = extract_iocs(
        text,
        excluded_urls=excluded_urls,
        excluded_hosts=excluded_hosts,
    )

    assert result.observables == ()


@pytest.mark.parametrize(
    "text",
    [
        "IOC contact user@evil.co",
        "IOC contact user@sub.evil.co",
        "IOC contact analyst@deep.sub.evil.co",
        "IOC contact mailto:user@sub.evil.co",
        "IOC contact user@a.b.c.d.e.f.g.h.i.j.k.evil.co",
        "IOC contact user@a[.]b[.]c[.]d[.]e[.]f[.]g[.]h[.]i[.]j[.]k[.]evil[.]co",
        "IOC contact user@[8.8.8.8]",
        "IOC contact user@[2606:4700:4700::1111]",
        "IOC contact user@8.8.8.8",
        "IOC contact " + ("a" * 65) + "@evil.co",
        "IOC contact user@" + ("a" * 64) + ".evil.co",
        "IOC contact USER@DEEP.SUB.EVIL.CO",
        "IOC contact user+case@deep.sub.evil.co",
        "IOC contact (user@deep.sub.evil.co)",
        "IOC contact user@deep.sub.evil.co,",
        "IOC contact user@deep[.]sub[.]evil[.]co",
        "IOC contact user@deep(.)sub(.)evil(.)co",
        f"IOC contact {SHA256}@evil.co",
        "IOC contact @sub.evil.co",
        "IOC contact @a.b.c.d.e.f.g.h.i.j.k.evil.co",
        "IOC contact @sub[.]evil[.]co",
        "IOC contact @sub(.)evil(.)co",
        "IOC contact @8.8.8.8",
        "IOC contact @[8.8.8.8]",
        "IOC contact @2606:4700:4700::1111",
        "IOC contact @[2606:4700:4700::1111]",
        "IOC contact @SUB.EVIL.CO",
        "IOC contact (@sub.evil.co),",
    ],
)
def test_every_ioc_candidate_inside_bounded_email_like_tokens_is_suppressed(text):
    assert extract_iocs(text).observables == ()


def test_email_suppression_does_not_hide_a_separate_contextual_domain():
    result = extract_iocs(
        "IOC contact analyst@deep.sub.evil.co and domain separate-ioc.co"
    )

    assert _values(result) == [("domain", "separate-ioc.co")]


def test_email_address_literal_suppression_does_not_hide_a_separate_ip():
    result = extract_iocs("Contact user@[8.8.8.8]; IOC IP 1.1.1.1")

    assert _values(result) == [("ipv4", "1.1.1.1")]


def test_leading_at_suppression_does_not_hide_a_separate_contextual_domain():
    result = extract_iocs(
        "Contact @sub.evil.co; IOC domain separate-ioc.co"
    )

    assert _values(result) == [("domain", "separate-ioc.co")]


def test_leading_at_address_literal_does_not_hide_a_separate_ip():
    result = extract_iocs("Contact @[8.8.8.8]; IOC IP 1.1.1.1")

    assert _values(result) == [("ipv4", "1.1.1.1")]


@pytest.mark.parametrize(
    "candidate",
    [
        "https://[2606:4700:4700::1111]",
        "https://[2606:4700:4700::1111]/",
        "https://[2606:4700:4700::1111].",
    ],
)
def test_bracketed_ipv6_root_urls_preserve_authority_and_suppress_host(candidate):
    result = extract_iocs(f"IOC URL {candidate}")

    assert _values(result) == [("url", "https://[2606:4700:4700::1111]/")]


@pytest.mark.parametrize(
    "candidate",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.10.20",
        "224.0.0.1",
        "0.0.0.0",
        "192.0.2.10",
        "2001:db8::1",
        "::1",
        "ff02::1",
    ],
)
def test_non_global_ips_are_rejected(candidate):
    assert extract_iocs(f"malicious IOC IP {candidate}").observables == ()


@pytest.mark.parametrize(
    ("candidate", "excluded_host"),
    [
        ("8.8.8.8", "8.8.8.8"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
    ],
)
def test_canonical_ip_candidates_honor_excluded_hosts(candidate, excluded_host):
    result = extract_iocs(
        f"IOC IP {candidate}",
        excluded_hosts=(excluded_host,),
    )

    assert result.observables == ()


def test_canonical_domain_candidates_still_honor_excluded_hosts():
    result = extract_iocs(
        "IOC domain excluded-domain.co",
        excluded_hosts=("EXCLUDED-DOMAIN.CO",),
    )

    assert result.observables == ()


@pytest.mark.parametrize(
    "text",
    [
        "version 8.8.8.8",
        "version: 8.8.8.8",
        "release 8.8.8.8",
        "build 8.8.8.8",
        "v8.8.8.8",
        "IOC parser version 8.8.8.8 released",
    ],
)
def test_literal_dotted_software_versions_are_not_ipv4_observables(text):
    assert extract_iocs(text).observables == ()


@pytest.mark.parametrize(
    "text",
    [
        "malicious IP address 8.8.8.8",
        "IOC IP 8.8.8.8",
        "C2 address 8.8.8.8",
        "release IOC IP 8.8.8.8",
    ],
)
def test_explicit_ip_context_continues_to_accept_literal_global_ipv4(text):
    assert _values(extract_iocs(text)) == [("ipv4", "8.8.8.8")]


def test_defanged_ipv4_remains_stronger_than_version_wording():
    assert _values(extract_iocs("version 8[.]8[.]8[.]8")) == [
        ("ipv4", "8.8.8.8")
    ]


@pytest.mark.parametrize(
    "text",
    [
        "malicious Python package requests.utils",
        "IOC package package.name",
        "IOC module com.example.malware",
        "IOC library library.component",
        "IOC dependency dependency.component",
        "IOC import requests.utils",
        "IOC filename config.yaml",
        "IOC file payload.bin",
        "IOC path /opt/config.yaml",
        r"IOC path C:\temp\config.yaml",
    ],
)
def test_package_module_and_file_tokens_are_not_domains(text):
    assert extract_iocs(text).observables == ()


@pytest.mark.parametrize(
    "text",
    [
        "IOC file report lists domain genuine-domain.co",
        "IOC package report lists host genuine-host.co",
        "IOC module report lists C2 genuine-c2.co",
        "IOC filename report lists URL genuine-url.co",
        "IOC package genuine-defanged[.]co",
    ],
)
def test_explicit_or_defanged_domain_intent_survives_token_guards(text):
    expected = text.split()[-1].replace("[.]", ".")
    assert _values(extract_iocs(text)) == [("domain", expected)]


@pytest.mark.parametrize(
    "text",
    [
        "Release 1.2.3.4 is available",
        "Contact analyst@malicious.co for details",
        "Download malware.exe package.name",
        "A sentence happens to include ambiguous.co",
        MD5,
        "hash " + "a" * 64,
        "IOC hxxps://mixed[.]bad(.)co/a",
        "IOC ftp://malicious.co/a",
        "IOC https://user:password@malicious.co/a",
        "IOC https://malicious.co:99999/a",
        "IOC domain \ud800.co",
    ],
)
def test_ambiguous_or_unsafe_text_is_rejected(text):
    assert extract_iocs(text).observables == ()


def test_source_urls_and_hosts_are_excluded_without_network_validation():
    result = extract_iocs(
        "IOC https://publisher.co/story and domain publisher.co and source.co",
        excluded_urls=("https://publisher.co/story",),
        excluded_hosts=("source.co",),
    )

    assert result.observables == ()


@pytest.mark.parametrize("control", ["\x00", "\n", "\t", "\x85", "\x9f"])
def test_unicode_control_characters_are_rejected(control):
    with pytest.raises(
        IOCTextExtractionError,
        match="Publication text contains unsupported controls",
    ):
        extract_iocs(f"IOC domain bad.co{control}")


def test_overlong_text_is_reported_without_partial_processing():
    result = extract_iocs("A" * 12_001 + " IOC bad[.]co")

    assert result.status == "rejected_text_limit"
    assert result.observables == ()
    assert result.limit_reached is True


def test_candidate_limits_are_reported_and_processing_remains_bounded():
    text = " IOC ".join(f"host-{index}[.]co" for index in range(MAX_TOTAL_CANDIDATES + 5))
    result = extract_iocs(text)

    assert result.status == "bounded"
    assert result.limit_reached is True
    assert len(result.observables) == 25
    assert result.candidates_found == 25
    assert result.rejected_candidates == 0


def test_total_candidate_limit_stops_cross_type_inspection():
    urls = [f"https://url-{index}.co/a" for index in range(20)]
    ipv4 = [f"8.8.{index}.1" for index in range(25)]
    ipv6 = [f"2606:4700::{index + 1:x}" for index in range(20)]
    hashes = [f"{index + 1:064x}" for index in range(20)]
    domains = [f"domain-{index}[.]co" for index in range(20)]
    text = "IOC URL " + " ".join(urls)
    text += " IOC IP " + " ".join(ipv4 + ipv6)
    text += " SHA256 " + " ".join(hashes)
    text += " IOC domain " + " ".join(domains)

    result = extract_iocs(text)

    assert result.status == "bounded"
    assert result.limit_reached is True
    assert result.candidates_found == MAX_TOTAL_CANDIDATES


def test_context_is_collapsed_and_bounded():
    result = extract_iocs("IOC " + ("word " * 80) + "bad[.]co" + (" tail" * 80))

    context = result.observables[0].context_summary
    assert len(context) <= MAX_CONTEXT_SUMMARY_LENGTH
    assert "  " not in context


def test_extraction_performs_no_socket_dns_or_http_access(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("offline extraction attempted network access")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(httpx, "request", fail)
    monkeypatch.setattr(httpx.Client, "request", fail)

    result = extract_iocs("IOC https://malicious.co/a and domain bad[.]co")

    assert len(result.observables) == 2
