"""``scripts/bootstrap_env.py``: generated credentials, no overwrite, private file mode."""

from __future__ import annotations

import importlib.util
import stat
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bootstrap_env.py"
EXAMPLE = (Path(__file__).resolve().parents[2] / ".env.example").read_text(encoding="utf-8")


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bootstrap_env", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / ".env.example").write_text(EXAMPLE, encoding="utf-8")
    return tmp_path


def values(path: Path) -> dict[str, str]:
    pairs = (line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
    return {k: v for k, v in pairs if not k.startswith("#")}


def test_credentials_are_generated_random_and_long(project: Path) -> None:
    script = load_script()
    assert script.bootstrap(project) is True
    env = values(project / ".env")
    assert len(env["GUARDBENCH_API_KEY"]) >= 40
    assert len(env["POSTGRES_PASSWORD"]) >= 30
    assert env["POSTGRES_PASSWORD"] != "change-me-local-lab-only"


def test_two_runs_produce_different_credentials(
    project: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    script = load_script()
    other = tmp_path_factory.mktemp("second")
    (other / ".env.example").write_text(EXAMPLE, encoding="utf-8")
    script.bootstrap(project)
    script.bootstrap(other)
    assert values(project / ".env")["GUARDBENCH_API_KEY"] != values(other / ".env")["GUARDBENCH_API_KEY"]


def test_everything_else_in_the_template_is_preserved(project: Path) -> None:
    script = load_script()
    script.bootstrap(project)
    generated, template = values(project / ".env"), values(project / ".env.example")
    for key, value in template.items():
        if key not in {"GUARDBENCH_API_KEY", "POSTGRES_PASSWORD"}:
            assert generated[key] == value, key


def test_an_existing_env_file_is_never_overwritten(project: Path) -> None:
    script = load_script()
    (project / ".env").write_text("GUARDBENCH_API_KEY=mine\n", encoding="utf-8")
    assert script.bootstrap(project) is False
    assert (project / ".env").read_text() == "GUARDBENCH_API_KEY=mine\n"


def test_force_regenerates(project: Path) -> None:
    script = load_script()
    (project / ".env").write_text("GUARDBENCH_API_KEY=old\n", encoding="utf-8")
    assert script.bootstrap(project, force=True) is True
    assert values(project / ".env")["GUARDBENCH_API_KEY"] != "old"


def test_the_file_is_private_to_the_owner(project: Path) -> None:
    script = load_script()
    script.bootstrap(project)
    assert stat.S_IMODE((project / ".env").stat().st_mode) == 0o600


def test_generated_values_are_never_printed(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    script = load_script()
    assert script.main([], root=project) == 0
    key = values(project / ".env")["GUARDBENCH_API_KEY"]
    password = values(project / ".env")["POSTGRES_PASSWORD"]
    out = capsys.readouterr().out
    assert "created" in out and key not in out and password not in out
    assert script.main([], root=project) == 0
    assert "already exists" in capsys.readouterr().out


def test_a_template_without_the_expected_lines_is_rejected() -> None:
    script = load_script()
    with pytest.raises(SystemExit, match="GUARDBENCH_API_KEY"):
        script.render("POSTGRES_PASSWORD=x\n")
    with pytest.raises(SystemExit, match="POSTGRES_PASSWORD"):
        script.render("GUARDBENCH_API_KEY=\n")
