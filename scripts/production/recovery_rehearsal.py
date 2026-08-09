"""Contract checks and label-gated isolated Docker recovery rehearsals for C09."""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic, sleep
from typing import Callable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPOSITORY_ROOT / "compose.prod.yml"
PROJECT_PATTERN = re.compile(r"^alpha-data-rehearsal-[a-z0-9]{8,32}$")
PROHIBITED_PROJECTS = frozenset({"alpha-data-production", "alpha_data_production"})
ALEMBIC_HEAD = "c07a01b02c03"
SCENARIOS = (
    "application_rollback",
    "failed_deployment",
    "migration_failure",
    "worker_outage",
    "source_outage",
    "credential_failure",
    "partial_ingestion_checkpoint",
    "backup_restore",
)
OPERATIONAL_UNRUN = {
    "source_outage": (
        "UNRUN: no approved runtime fault-injection interface exists for a source without "
        "activating a disabled handler; contract tests remain separate."
    ),
    "partial_ingestion_checkpoint": (
        "UNRUN: transactional fault injection is available only through the existing isolated "
        "persistence contract tests; it is not represented as an operational recovery."
    ),
    "backup_restore": (
        "UNRUN in this harness: host age/PostgreSQL clients are unavailable and delegating the "
        "Docker socket to a tool container is outside the approved boundary; run the separately "
        "documented encrypted restore rehearsal instead."
    ),
}


class RehearsalError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario: str
    started_utc: str
    completed_utc: str
    elapsed_seconds: float
    success: bool
    data_loss_observation: str
    safe_notes: str


@dataclass(frozen=True, slots=True)
class OperationalResult:
    scenario: str
    started_utc: str
    completed_utc: str
    elapsed_seconds: float
    status: str
    data_loss_observation: str
    safe_notes: str


def validate_project_name(name: str) -> str:
    if name in PROHIBITED_PROJECTS or PROJECT_PATTERN.fullmatch(name) is None:
        raise RehearsalError("The rehearsal project name is invalid or unsafe.")
    return name


def validate_compose_environment(path: Path) -> Path:
    """Accept only a bounded non-symlink synthetic environment under repository tmp."""

    try:
        if path.is_symlink():
            raise RehearsalError("The rehearsal environment file is invalid.")
        metadata = path.stat()
        resolved = path.resolve(strict=True)
        tmp_root = (REPOSITORY_ROOT / "tmp").resolve(strict=True)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= 65536
            or tmp_root not in resolved.parents
        ):
            raise RehearsalError("The rehearsal environment file is invalid.")
        values = {}
        for line in resolved.read_text(encoding="utf-8").splitlines():
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    except RehearsalError:
        raise
    except (OSError, UnicodeError):
        raise RehearsalError("The rehearsal environment file is invalid.") from None
    if (
        not values.get("EDGE_HOST", "").endswith(".invalid")
        or values.get("EDGE_BIND_ADDRESS") != "127.0.0.1"
        or values.get("APP_ENV", "production") != "production"
    ):
        raise RehearsalError("The rehearsal environment is not isolated and synthetic.")
    return resolved


def _utc() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fixed_validation_command(scenario: str) -> list[str]:
    python = str(REPOSITORY_ROOT / "backend" / ".venv" / "Scripts" / "python.exe")
    tests = {
        "application_rollback": ["tests/test_c09_recovery.py", "-k", "rollback_contract"],
        "failed_deployment": ["tests/test_c09_recovery.py", "-k", "failed_deployment_contract"],
        "migration_failure": ["tests/test_alembic_config.py"],
        "worker_outage": ["tests/test_c09_system_health.py", "-k", "overall_health_semantics"],
        "source_outage": ["tests/test_orchestration_flows.py", "-k", "failure"],
        "credential_failure": ["tests/test_c09_backup_restore.py", "-k", "secret"],
        "partial_ingestion_checkpoint": ["tests/test_orchestration_persistence.py", "tests/test_operational_persistence_service.py"],
        "backup_restore": ["tests/test_c09_backup_restore.py"],
    }
    if scenario not in tests:
        raise RehearsalError("The recovery scenario is not allow-listed.")
    return [python, "-m", "pytest", "-q", *tests[scenario]]


def run_scenario(
    scenario: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    clock: Callable[[], float] = monotonic,
) -> ScenarioResult:
    command = fixed_validation_command(scenario)
    started_utc = _utc()
    started = clock()
    try:
        completed = runner(
            command,
            cwd=REPOSITORY_ROOT / "backend",
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        success = completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        success = False
    elapsed = max(0.0, clock() - started)
    return ScenarioResult(
        scenario=scenario,
        started_utc=started_utc,
        completed_utc=_utc(),
        elapsed_seconds=round(elapsed, 3),
        success=success,
        data_loss_observation=(
            "zero_in_synthetic_contract" if success and scenario in {"partial_ingestion_checkpoint", "backup_restore"} else "not_measured"
        ),
        safe_notes=(
            "Fixed offline contract validation passed; this is not an operational rehearsal or production RTO evidence."
            if success
            else "Fixed offline contract validation failed; no recovery success is claimed."
        ),
    )


class DockerOperationalRehearsal:
    """Perform fixed actions only against Compose-label-verified rehearsal resources."""

    def __init__(
        self,
        project: str,
        environment_file: Path,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        clock: Callable[[], float] = monotonic,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self.project = validate_project_name(project)
        self.environment_file = validate_compose_environment(environment_file)
        self._runner = runner
        self._clock = clock
        self._sleep = sleeper
        self._base = [
            "docker", "compose", "-p", self.project, "--env-file",
            str(self.environment_file), "-f", str(COMPOSE_FILE),
        ]

    def _run(self, command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        try:
            return self._runner(
                command,
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise RehearsalError("The isolated Docker rehearsal command failed safely.") from None

    def _compose(self, *arguments: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return self._run([*self._base, *arguments], timeout=timeout)

    def _owned_container(self, service: str) -> str:
        if service not in {"db", "backend", "prefect-worker", "reverse-proxy"}:
            raise RehearsalError("The rehearsal service is not allow-listed.")
        discovered = self._compose("ps", "--all", "--quiet", service, timeout=30)
        container_id = discovered.stdout.strip()
        if discovered.returncode != 0 or re.fullmatch(r"[0-9a-f]{12,64}", container_id) is None:
            raise RehearsalError("The rehearsal service container is unavailable.")
        inspected = self._run(
            [
                "docker", "inspect", "--format",
                '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}',
                container_id,
            ],
            timeout=30,
        )
        if inspected.returncode != 0 or inspected.stdout.strip() != f"{self.project}|{service}":
            raise RehearsalError("The Docker resource ownership label check failed.")
        return container_id

    def _health(self, service: str, *, timeout: int = 90) -> None:
        deadline = self._clock() + timeout
        while self._clock() <= deadline:
            try:
                container_id = self._owned_container(service)
                state = self._run(
                    ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_id],
                    timeout=30,
                )
                if state.returncode == 0 and state.stdout.strip() == "healthy":
                    return
            except RehearsalError:
                pass
            self._sleep(1)
        raise RehearsalError("The rehearsal service did not become healthy.")

    def _stop(self, service: str) -> None:
        self._owned_container(service)
        stopped = self._compose("stop", "--timeout", "10", service, timeout=30)
        if stopped.returncode != 0:
            raise RehearsalError("The rehearsal service could not be stopped safely.")

    def _restore_service(self, service: str) -> None:
        self._owned_container(service)
        restored = self._compose("up", "-d", "--no-deps", service, timeout=120)
        if restored.returncode != 0:
            raise RehearsalError("The known-good rehearsal service could not be restored.")
        self._health(service)

    def _invalid_backend_candidate(self, *, credential_failure: bool = False) -> None:
        command = ["run", "--rm", "--no-deps"]
        if credential_failure:
            command.extend(["-e", "POSTGRES_PASSWORD_FILE=/run/secrets/c09-synthetic-missing"])
            probe = (
                "from app.core.config import get_settings; "
                "get_settings().sqlalchemy_database_url"
            )
            command.extend(["backend", "python", "-c", probe])
        else:
            command.extend(["-e", "APP_COMMIT_SHA=invalid", "backend"])
        candidate = self._compose(*command, timeout=90)
        if candidate.returncode == 0:
            raise RehearsalError("The synthetic failing candidate was not detected correctly.")

    def _worker_metric(self, state: str, *, timeout: int = 45) -> None:
        expected = f'alpha_data_component_health{{component="prefect_worker",state="{state}"}} 1'
        probe = (
            "import urllib.request; from app.core.config import get_settings; "
            "request=urllib.request.Request('http://127.0.0.1:8000/internal/metrics',"
            "headers={'Host':get_settings().trusted_hosts_list[0]}); "
            "body=urllib.request.urlopen(request,timeout=5).read().decode(); "
            f"raise SystemExit(0 if {expected!r} in body else 1)"
        )
        deadline = self._clock() + timeout
        while self._clock() <= deadline:
            result = self._compose("exec", "-T", "backend", "python", "-c", probe, timeout=15)
            if result.returncode == 0:
                return
            self._sleep(1)
        raise RehearsalError("Worker health degradation/recovery was not observed internally.")

    def application_rollback(self) -> str:
        self._health("backend")
        self._health("reverse-proxy")
        self._stop("backend")
        try:
            self._invalid_backend_candidate()
        finally:
            self._restore_service("backend")
        self._health("reverse-proxy")
        return "A failing immutable rehearsal candidate was rejected and the known-good backend recovered healthy."

    def failed_deployment(self) -> str:
        self._health("backend")
        self._invalid_backend_candidate()
        self._restore_service("backend")
        self._health("reverse-proxy")
        return "Invalid deployment identity failed startup; the known-good configuration remained healthy."

    def migration_failure(self) -> str:
        self._health("db")
        self._health("backend")
        failed = self._compose(
            "--profile", "migration", "run", "--rm", "--no-deps",
            "-e", "POSTGRES_DB=alpha_data_restore_migrationtest", "migrate",
            "alembic", "-c", "/app/c09-intentional-missing.ini", "upgrade", "head",
            timeout=90,
        )
        if failed.returncode == 0:
            raise RehearsalError("The deterministic migration failure was not detected.")
        self._health("db")
        self._health("backend")
        history = self._compose(
            "exec", "-T", "backend", "alembic", "-c", "/app/alembic.ini", "heads",
            timeout=30,
        )
        if history.returncode != 0 or ALEMBIC_HEAD not in history.stdout:
            raise RehearsalError("The known-good Alembic head could not be confirmed.")
        return "A deterministic throwaway-target migration command failed closed; the known-good database/head remained healthy."

    def worker_outage(self) -> str:
        self._health("prefect-worker")
        self._stop("prefect-worker")
        try:
            self._worker_metric("unhealthy")
        finally:
            self._restore_service("prefect-worker")
        self._worker_metric("healthy")
        return "Only the label-verified rehearsal worker was stopped; internal metrics observed outage and recovery."

    def credential_failure(self) -> str:
        self._health("backend")
        self._invalid_backend_candidate(credential_failure=True)
        self._health("backend")
        return "A missing synthetic credential reference failed closed while the known-good backend remained healthy."

    def execute(self, scenario: str) -> str:
        handlers = {
            "application_rollback": self.application_rollback,
            "failed_deployment": self.failed_deployment,
            "migration_failure": self.migration_failure,
            "worker_outage": self.worker_outage,
            "credential_failure": self.credential_failure,
        }
        if scenario not in handlers:
            raise RehearsalError("The operational recovery scenario is unavailable.")
        return handlers[scenario]()


def run_operational_scenario(
    rehearsal: DockerOperationalRehearsal,
    scenario: str,
) -> OperationalResult:
    started_utc = _utc()
    started = rehearsal._clock
    begin = started()
    if scenario in OPERATIONAL_UNRUN:
        return OperationalResult(
            scenario=scenario,
            started_utc=started_utc,
            completed_utc=_utc(),
            elapsed_seconds=0.0,
            status="unrun",
            data_loss_observation="not_measured",
            safe_notes=OPERATIONAL_UNRUN[scenario],
        )
    try:
        note = rehearsal.execute(scenario)
        status = "pass"
    except RehearsalError:
        note = "The isolated operational rehearsal failed safely; no recovery success is claimed."
        status = "fail"
    elapsed = max(0.0, started() - begin)
    return OperationalResult(
        scenario=scenario,
        started_utc=started_utc,
        completed_utc=_utc(),
        elapsed_seconds=round(elapsed, 3),
        status=status,
        data_loss_observation="not_measured",
        safe_notes=note,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Run isolated C09 recovery validation.")
    result.add_argument("--project-name", required=True)
    result.add_argument("--synthetic-only", action="store_true", required=True)
    result.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="all")
    result.add_argument("--mode", choices=("contract", "operational", "both"), default="contract")
    result.add_argument("--compose-env-file", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        project = validate_project_name(arguments.project_name)
        if arguments.mode in {"operational", "both"} and arguments.compose_env_file is None:
            raise RehearsalError("Operational mode requires an isolated Compose environment file.")
        rehearsal = (
            DockerOperationalRehearsal(project, arguments.compose_env_file)
            if arguments.mode in {"operational", "both"}
            else None
        )
    except RehearsalError as error:
        print(str(error), file=sys.stderr)
        return 2
    selected = SCENARIOS if arguments.scenario == "all" else (arguments.scenario,)
    contract_results = (
        [run_scenario(scenario) for scenario in selected]
        if arguments.mode in {"contract", "both"}
        else []
    )
    operational_results = (
        [run_operational_scenario(rehearsal, scenario) for scenario in selected]
        if rehearsal is not None
        else []
    )
    document = {
        "environment": "isolated local synthetic recovery validation",
        "project_name": project,
        "live_sources_used": False,
        "rpo_target_hours": 24,
        "rto_target_hours": 2,
        "rpo_rto_demonstrated": False,
        "contract_results": [asdict(result) for result in contract_results],
        "operational_results": [asdict(result) for result in operational_results],
    }
    print(json.dumps(document, sort_keys=True))
    contract_ok = all(result.success for result in contract_results)
    operational_ok = all(result.status != "fail" for result in operational_results)
    return 0 if contract_ok and operational_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
