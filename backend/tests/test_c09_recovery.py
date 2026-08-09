from pathlib import Path
import json
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.production import recovery_rehearsal as harness  # noqa: E402


@pytest.mark.parametrize("name", ["alpha-data-production", "alpha_data_production", "production", "alpha-data-rehearsal-../bad", "alpha-data-rehearsal-short"])
def test_production_and_invalid_project_names_are_rejected(name: str) -> None:
    with pytest.raises(harness.RehearsalError):
        harness.validate_project_name(name)


def test_synthetic_rehearsal_project_is_accepted() -> None:
    assert harness.validate_project_name("alpha-data-rehearsal-deadbeef") == "alpha-data-rehearsal-deadbeef"


def test_failed_scenario_is_not_marked_success_and_uses_monotonic_time() -> None:
    moments = iter([10.0, 12.5])
    result = harness.run_scenario(
        "worker_outage",
        runner=lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "raw failure"),
        clock=lambda: next(moments),
    )
    assert result.success is False
    assert result.elapsed_seconds == 2.5
    assert result.data_loss_observation == "not_measured"
    assert "raw failure" not in result.safe_notes


def test_partial_ingestion_uses_real_checkpoint_and_persistence_tests() -> None:
    command = " ".join(harness.fixed_validation_command("partial_ingestion_checkpoint"))
    assert "test_orchestration_persistence.py" in command
    assert "test_operational_persistence_service.py" in command
    assert "http://" not in command and "https://" not in command


def test_backup_restore_uses_the_real_backup_contract_tests() -> None:
    assert any(item.endswith("test_c09_backup_restore.py") for item in harness.fixed_validation_command("backup_restore"))


def test_rollback_contract() -> None:
    assert any(item.endswith("test_c09_recovery.py") for item in harness.fixed_validation_command("application_rollback"))


def test_failed_deployment_contract() -> None:
    assert any(item.endswith("test_c09_recovery.py") for item in harness.fixed_validation_command("failed_deployment"))


def test_successful_contract_does_not_claim_rpo_or_rto() -> None:
    moments = iter([1.0, 1.2])
    result = harness.run_scenario(
        "backup_restore",
        runner=lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
        clock=lambda: next(moments),
    )
    assert result.success is True
    assert "not an operational rehearsal" in result.safe_notes


def _synthetic_environment(tmp_path: Path, monkeypatch) -> Path:
    repository = tmp_path / "repository"
    environment_root = repository / "tmp" / "c09"
    environment_root.mkdir(parents=True)
    environment = environment_root / "validation.env"
    environment.write_text(
        "EDGE_HOST=c09-validation.example.invalid\n"
        "EDGE_BIND_ADDRESS=127.0.0.1\n"
        "APP_ENV=production\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(harness, "REPOSITORY_ROOT", repository)
    return environment


def test_operational_mode_requires_bounded_synthetic_environment(tmp_path: Path, monkeypatch) -> None:
    environment = _synthetic_environment(tmp_path, monkeypatch)
    assert harness.validate_compose_environment(environment) == environment.resolve()
    outside = tmp_path / "outside.env"
    outside.write_text("EDGE_HOST=real.example.com\nEDGE_BIND_ADDRESS=0.0.0.0\n", encoding="utf-8")
    with pytest.raises(harness.RehearsalError):
        harness.validate_compose_environment(outside)


def test_docker_ownership_labels_are_required_before_service_actions(tmp_path: Path, monkeypatch) -> None:
    environment = _synthetic_environment(tmp_path, monkeypatch)
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        if command[:2] == ["docker", "compose"] and "ps" in command:
            return subprocess.CompletedProcess(command, 0, "a" * 12 + "\n", "")
        if command[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(
                command, 0, "alpha-data-rehearsal-deadbeef|backend\n", ""
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    rehearsal = harness.DockerOperationalRehearsal(
        "alpha-data-rehearsal-deadbeef", environment, runner=runner
    )
    assert rehearsal._owned_container("backend") == "a" * 12
    assert any(command[:2] == ["docker", "inspect"] for command in calls)
    with pytest.raises(harness.RehearsalError):
        rehearsal._owned_container("unapproved-service")


def test_mismatched_docker_project_label_fails_closed(tmp_path: Path, monkeypatch) -> None:
    environment = _synthetic_environment(tmp_path, monkeypatch)

    def runner(command, **_kwargs):
        if command[:2] == ["docker", "compose"]:
            return subprocess.CompletedProcess(command, 0, "b" * 12 + "\n", "")
        return subprocess.CompletedProcess(command, 0, "alpha-data-production|backend\n", "")

    rehearsal = harness.DockerOperationalRehearsal(
        "alpha-data-rehearsal-deadbeef", environment, runner=runner
    )
    with pytest.raises(harness.RehearsalError, match="ownership label"):
        rehearsal._owned_container("backend")


def test_contract_and_operational_evidence_remain_separate(tmp_path: Path, monkeypatch, capsys) -> None:
    environment = _synthetic_environment(tmp_path, monkeypatch)
    monkeypatch.setattr(
        harness,
        "run_scenario",
        lambda scenario: harness.ScenarioResult(
            scenario, "start", "end", 0.1, True, "not_measured", "Contract passed."
        ),
    )
    monkeypatch.setattr(
        harness,
        "DockerOperationalRehearsal",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        harness,
        "run_operational_scenario",
        lambda _rehearsal, scenario: harness.OperationalResult(
            scenario, "start", "end", 0.2, "pass", "not_measured", "Operational passed."
        ),
    )
    code = harness.main(
        [
            "--project-name", "alpha-data-rehearsal-deadbeef",
            "--synthetic-only", "--scenario", "worker_outage", "--mode", "both",
            "--compose-env-file", str(environment),
        ]
    )
    document = json.loads(capsys.readouterr().out)
    assert code == 0
    assert document["contract_results"][0]["safe_notes"] == "Contract passed."
    assert document["operational_results"][0]["safe_notes"] == "Operational passed."
    assert document["rpo_rto_demonstrated"] is False


@pytest.mark.parametrize("scenario", ["source_outage", "partial_ingestion_checkpoint", "backup_restore"])
def test_unavailable_operational_scenarios_are_truthfully_unrun(scenario: str) -> None:
    class Rehearsal:
        _clock = staticmethod(iter([1.0]).__next__)

    result = harness.run_operational_scenario(Rehearsal(), scenario)
    assert result.status == "unrun"
    assert result.elapsed_seconds == 0.0
    assert result.safe_notes.startswith("UNRUN")


def test_recovery_harness_uses_argument_arrays_and_never_shell_true() -> None:
    source = (ROOT / "scripts" / "production" / "recovery_rehearsal.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert '"docker", "compose"' in source
    assert "com.docker.compose.project" in source
    assert "alpha-data-production" in source
