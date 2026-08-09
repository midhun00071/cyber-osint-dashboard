from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "compose.prod.yml").read_text(encoding="utf-8"))
CADDY = (ROOT / "ops" / "caddy" / "Caddyfile").read_text(encoding="utf-8")
CADDY_DOCKERFILE = (ROOT / "ops" / "caddy" / "Dockerfile").read_text(encoding="utf-8")


def test_only_edge_publishes_host_ports() -> None:
    published = {name for name, service in COMPOSE["services"].items() if "ports" in service}
    assert published == {"reverse-proxy"}
    assert len(COMPOSE["services"]["reverse-proxy"]["ports"]) == 2
    for private in ("db", "backend", "frontend", "prefect-server", "prefect-worker", "prometheus", "alertmanager"):
        assert "ports" not in COMPOSE["services"][private]


def test_caddy_derivative_is_pinned_non_root_and_needs_no_linux_capability() -> None:
    service = COMPOSE["services"]["reverse-proxy"]

    assert CADDY_DOCKERFILE.startswith("FROM caddy:2.10.2-alpine@sha256:")
    assert "setcap -r /usr/bin/caddy" in CADDY_DOCKERFILE
    assert "USER 10001:10001" in CADDY_DOCKERFILE
    assert service["user"] == "10001:10001"
    assert service["cap_drop"] == ["ALL"]


def test_edge_uses_exact_host_high_internal_ports_and_real_tls_default() -> None:
    assert "http://{$EDGE_HOST}:8080" in CADDY
    assert "https://{$EDGE_HOST}:8443" in CADDY
    assert "tls {$EDGE_TLS_MODE}" in CADDY
    assert "redir https://{$EDGE_HOST}:{$EDGE_HTTPS_PORT}{uri} permanent" in CADDY
    assert "protocols h1 h2" in CADDY
    assert "://*" not in CADDY
    assert "admin off" in CADDY


def test_hsts_and_browser_headers_exist_only_in_https_site() -> None:
    http_site, https_site = CADDY.split("https://{$EDGE_HOST}:8443", maxsplit=1)
    assert "Strict-Transport-Security" not in http_site
    assert "Strict-Transport-Security" in https_site
    for header in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"):
        assert header in https_site
    for directive in ("default-src", "script-src", "style-src", "img-src", "connect-src", "font-src", "object-src", "base-uri", "frame-ancestors", "form-action"):
        assert directive in https_site


def test_edge_bounds_body_and_upstream_timeouts_and_rejects_internal_paths() -> None:
    assert "max_size 1MB" in CADDY
    assert "read_body 10s" in CADDY and "write 30s" in CADDY
    assert CADDY.count("dial_timeout 3s") == 2
    assert CADDY.count("response_header_timeout 15s") == 2
    assert "@internal path /internal/*" in CADDY
    assert "respond @internal 404" in CADDY
    assert "reverse_proxy backend:8000" in CADDY
    assert "reverse_proxy frontend:3000" in CADDY
    for prohibited in ("prefect-server:4200", "prefect-worker:8080", "prometheus:9090", "alertmanager:9093", "db:5432"):
        assert prohibited not in CADDY


def test_networks_keep_admin_surfaces_away_from_edge() -> None:
    services = COMPOSE["services"]
    assert services["reverse-proxy"]["networks"] == ["edge"]
    assert services["prometheus"]["networks"] == ["monitoring"]
    assert services["alertmanager"]["networks"] == ["monitoring"]
    assert "monitoring" not in services["reverse-proxy"]["networks"]
    assert set(services["backend"]["networks"]) == {"edge", "database", "orchestration", "monitoring"}
    assert COMPOSE["networks"]["database"]["internal"] is True
    assert COMPOSE["networks"]["monitoring"]["internal"] is True
    assert "internal" not in COMPOSE["networks"]["orchestration"]
