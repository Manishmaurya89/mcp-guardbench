"""Static checks on the Docker artifacts.

The Docker daemon is not needed (or used) here: these tests parse ``docker-compose.yml``,
``Dockerfile`` and ``.dockerignore`` and assert the isolation properties the project promises. They
turn a written safety claim into something CI can fail on.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[2]
POSTGRES_CAPABILITIES = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    loaded = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@pytest.fixture(scope="module")
def services(compose: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found = compose["services"]
    assert {"postgres", "api", "dashboard", "test-runner"} <= set(found)
    return found  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text(encoding="utf-8")


# ---------------------------------------------------------------- compose: isolation


def test_no_service_is_privileged_or_uses_the_host_namespaces(services: dict[str, dict[str, Any]]) -> None:
    for name, service in services.items():
        assert not service.get("privileged"), name
        for key in ("network_mode", "pid", "ipc", "userns_mode", "uts"):
            assert service.get(key) in (None, "private"), (name, key)
        assert not service.get("devices"), name


def test_the_docker_socket_and_host_paths_are_never_mounted(compose: dict[str, Any]) -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "docker.sock" not in text
    for name, service in compose["services"].items():
        for volume in service.get("volumes", []):
            source = volume.split(":")[0] if isinstance(volume, str) else volume.get("source", "")
            # Only named volumes and the reports directory may be mounted.
            assert source in {"pgdata", "./reports"}, (name, volume)


def test_every_service_drops_all_capabilities_and_blocks_privilege_escalation(
    services: dict[str, dict[str, Any]],
) -> None:
    for name, service in services.items():
        assert service.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in service.get("security_opt", []), name


def test_only_postgres_may_add_capabilities_and_only_the_five_it_needs(
    services: dict[str, dict[str, Any]],
) -> None:
    for name, service in services.items():
        added = set(service.get("cap_add", []))
        if name == "postgres":
            assert added == POSTGRES_CAPABILITIES
        else:
            assert not added, name


def test_root_filesystems_are_read_only_with_tmpfs_for_scratch_space(
    services: dict[str, dict[str, Any]],
) -> None:
    for name, service in services.items():
        assert service.get("read_only") is True, name
        assert "/tmp" in service.get("tmpfs", []), name


def test_every_service_has_resource_limits(services: dict[str, dict[str, Any]]) -> None:
    for name, service in services.items():
        assert service.get("mem_limit"), name
    for name in ("api", "dashboard", "postgres"):
        assert services[name].get("pids_limit"), name


# ---------------------------------------------------------------- compose: network


def test_ports_are_published_on_loopback_only(services: dict[str, dict[str, Any]]) -> None:
    for name, service in services.items():
        for port in service.get("ports", []):
            assert isinstance(port, str) and port.startswith("127.0.0.1:"), (name, port)
    assert not services["postgres"].get("ports"), "PostgreSQL must not be published at all"


def test_the_backend_network_is_internal_and_holds_the_attack_fixtures(
    compose: dict[str, Any], services: dict[str, dict[str, Any]]
) -> None:
    assert compose["networks"]["backend"].get("internal") is True
    for name in ("postgres", "migrate", "test-runner"):
        assert services[name]["networks"] == ["backend"], f"{name} must have no route to the internet"


def test_only_the_api_and_dashboard_join_the_edge_network(services: dict[str, dict[str, Any]]) -> None:
    on_edge = {name for name, s in services.items() if "edge" in s.get("networks", [])}
    assert on_edge == {"api", "dashboard"}


# ---------------------------------------------------------------- compose: secrets and mode


def test_credentials_are_required_from_the_environment_never_defaulted(compose: dict[str, Any]) -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "${GUARDBENCH_API_KEY:?" in text
    assert "${POSTGRES_PASSWORD:?" in text
    for line in text.splitlines():
        if re.search(r"(PASSWORD|API_KEY|SECRET|TOKEN)\s*:", line) and not line.lstrip().startswith("#"):
            assert "${" in line and ":?" in line, (
                f"credential must be required, not defaulted: {line.strip()}"
            )


def test_containers_run_with_dev_mode_off_so_the_api_key_is_enforced(compose: dict[str, Any]) -> None:
    env = compose["x-app-env"]
    assert env["GUARDBENCH_DEV_MODE"] == "false"
    assert "GUARDBENCH_API_KEY" in env


def test_the_dashboard_gets_no_database_credentials(services: dict[str, dict[str, Any]]) -> None:
    env = services["dashboard"]["environment"]
    assert not any("DATABASE" in key or "POSTGRES" in key for key in env)


def test_services_wait_for_healthy_dependencies(services: dict[str, dict[str, Any]]) -> None:
    assert services["migrate"]["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert services["api"]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert services["dashboard"]["depends_on"]["api"]["condition"] == "service_healthy"
    for name in ("postgres", "api", "dashboard"):
        assert services[name]["healthcheck"]["test"], name


def test_the_test_runner_is_opt_in(services: dict[str, dict[str, Any]]) -> None:
    assert services["test-runner"].get("profiles") == ["tools"]


# ---------------------------------------------------------------- Dockerfile


def test_the_image_runs_as_a_non_root_user(dockerfile: str) -> None:
    users = re.findall(r"^USER\s+(\S+)", dockerfile, flags=re.MULTILINE)
    assert users, "the Dockerfile must set USER"
    final = users[-1].split(":")[0]
    assert final not in {"root", "0"}
    assert final.isdigit() and int(final) >= 1000


def test_the_image_installs_only_from_the_local_wheel_build_and_fetches_no_scripts(dockerfile: str) -> None:
    assert not re.search(r"\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)", dockerfile)
    assert not re.search(r"^ADD\s+https?://", dockerfile, flags=re.MULTILINE)
    assert "--privileged" not in dockerfile
    assert "--trusted-host" not in dockerfile
    assert "--index-url http://" not in dockerfile


def test_the_image_bakes_in_no_secrets(dockerfile: str) -> None:
    for line in dockerfile.splitlines():
        if line.startswith(("ENV", "ARG")):
            assert not re.search(r"(KEY|PASSWORD|SECRET|TOKEN)\s*=", line, flags=re.IGNORECASE), line


def test_the_runtime_stage_does_not_copy_tests_or_env_files(dockerfile: str) -> None:
    runtime = dockerfile.split("AS runtime", 1)[1]
    copies = re.findall(r"^COPY\s+(?:--from=\S+\s+)?(.+)$", runtime, flags=re.MULTILINE)
    for copy in copies:
        assert "tests" not in copy.split() and ".env" not in copy


def test_dockerignore_keeps_local_secrets_and_data_out_of_the_build_context() -> None:
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for required in (".env", ".git", "data", ".venv", "tests"):
        assert required in ignored
    assert "!.env.example" in ignored


def test_the_example_env_holds_no_real_looking_credentials() -> None:
    from guardbench.domain.markers import find_credential_shapes

    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert find_credential_shapes(text) == []
    assert re.search(r"^GUARDBENCH_API_KEY=\s*$", text, flags=re.MULTILINE), "the example key must be empty"
