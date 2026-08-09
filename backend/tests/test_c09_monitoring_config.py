from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_prometheus_scrapes_only_private_backend_metrics_with_bounded_retention() -> None:
    config = yaml.safe_load((ROOT / "ops" / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))
    assert config["scrape_configs"] == [{"job_name": "alpha-data-backend", "metrics_path": "/internal/metrics", "scheme": "http", "static_configs": [{"targets": ["backend:8000"]}]}]
    compose = yaml.safe_load((ROOT / "compose.prod.yml").read_text(encoding="utf-8"))
    command = compose["services"]["prometheus"]["command"]
    assert "--storage.tsdb.retention.time=15d" in command
    assert "--storage.tsdb.retention.size=2GB" in command
    assert "ports" not in compose["services"]["prometheus"]


def test_alert_rules_cover_required_local_evidence_and_missing_backup() -> None:
    groups = yaml.safe_load((ROOT / "ops" / "prometheus" / "alerts.yml").read_text(encoding="utf-8"))["groups"]
    rules = {rule["alert"]: rule for group in groups for rule in group["rules"]}
    expected = {"AlphaDataBackendUnhealthy", "AlphaDataDatabaseUnhealthy", "AlphaDataPrefectServerUnhealthy", "AlphaDataWorkerUnhealthy", "AlphaDataSourceFreshnessDegraded", "AlphaDataSourceAttentionRequired", "AlphaDataIngestionCycleLate", "AlphaDataAuthenticationAbuse", "AlphaDataStoragePressure", "AlphaDataBackupEvidenceMissing"}
    assert set(rules) == expected
    assert "absent(alpha_data_backup_evidence_available)" in rules["AlphaDataBackupEvidenceMissing"]["expr"]
    assert rules["AlphaDataSourceFreshnessDegraded"]["expr"] == 'alpha_data_component_health{component="source_freshness",state="stale"} == 1'
    assert 'state="disabled"} == 0' in rules["AlphaDataSourceAttentionRequired"]["expr"]
    assert "alpha_data_source_attention_count > 0" in rules["AlphaDataSourceAttentionRequired"]["expr"]
    assert all(rule["labels"]["owner"] == "pending" for rule in rules.values())


def test_alertmanager_has_private_null_receiver_and_no_external_credentials() -> None:
    text = (ROOT / "ops" / "alertmanager" / "alertmanager.yml").read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    assert config["route"]["receiver"] == "local-null"
    assert config["receivers"] == [{"name": "local-null"}]
    for prohibited in ("slack", "webhook", "smtp", "email", "password", "token", "authorization"):
        assert prohibited not in text.lower()


def test_all_runtime_services_have_limits_health_and_bounded_logs() -> None:
    compose = yaml.safe_load((ROOT / "compose.prod.yml").read_text(encoding="utf-8"))
    for name, service in compose["services"].items():
        assert service["pids_limit"] > 0
        assert service["mem_limit"]
        assert service["cpus"] > 0
        if name != "migrate":
            assert service["healthcheck"]
        assert service["logging"]["options"] == {"max-size": "10m", "max-file": "3"}
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["cap_drop"] == ["ALL"]


def test_runtime_images_and_direct_dependencies_are_exactly_pinned() -> None:
    dockerfiles = [ROOT / "backend" / "Dockerfile.prod", ROOT / "frontend" / "Dockerfile.prod", ROOT / "prefect" / "Dockerfile"]
    for dockerfile in dockerfiles:
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            if line.startswith("FROM "):
                assert "@sha256:" in line
    requirements = (ROOT / "backend" / "requirements.prod.txt").read_text(encoding="utf-8").splitlines()
    assert requirements and all("==" in line for line in requirements)
    assert not any(line.startswith("pytest") for line in requirements)
    assert "requirements.prod.txt" in (ROOT / "backend" / "Dockerfile.prod").read_text(encoding="utf-8")
