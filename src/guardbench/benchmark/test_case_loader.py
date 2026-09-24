"""Load and validate ``test_cases/*.yaml``.

Loading is strict: unknown keys are errors, only ``yaml.safe_load`` is used, file sizes are
bounded, the directory is confined to the allowlisted test-case directory, and the fixture
must be on the lab allowlist. A malformed case fails loudly with its file name; it is never
silently skipped.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from guardbench.domain.errors import TestCaseError
from guardbench.domain.testcase import TestCaseSpec
from guardbench.mcp_lab.fixtures import fixture_names, is_allowed_fixture
from guardbench.safe_paths import confine

MAX_CASE_BYTES = 64 * 1024
MAX_CASES = 500
CASE_GLOB = "*.yaml"


@dataclass(frozen=True, slots=True)
class LoadedTestCase:
    """A validated test case plus where it came from."""

    spec: TestCaseSpec
    path: Path
    spec_hash: str


def parse_test_case(raw: bytes | str, *, source: str = "<inline>") -> TestCaseSpec:
    """Validate raw YAML into a :class:`TestCaseSpec`. Raises :class:`TestCaseError`."""
    data = raw.encode() if isinstance(raw, str) else raw
    if len(data) > MAX_CASE_BYTES:
        raise TestCaseError(f"{source}: test case is larger than {MAX_CASE_BYTES} bytes")
    try:
        document: Any = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise TestCaseError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise TestCaseError(f"{source}: a test case must be a YAML mapping")
    try:
        spec = TestCaseSpec.model_validate(document)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
        raise TestCaseError(f"{source}: {problems}") from exc
    if not is_allowed_fixture(spec.server_fixture):
        raise TestCaseError(
            f"{source}: fixture {spec.server_fixture!r} is not on the allowlist "
            f"({', '.join(fixture_names())})"
        )
    return spec


def load_test_case_file(path: Path) -> LoadedTestCase:
    """Load one file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TestCaseError(f"{path.name}: cannot read file: {exc.strerror}") from exc
    return LoadedTestCase(parse_test_case(raw, source=path.name), path, hashlib.sha256(raw).hexdigest())


def load_test_cases(directory: Path, *, allowed_root: Path) -> list[LoadedTestCase]:
    """Load every ``*.yaml`` in ``directory``, which must lie inside ``allowed_root``.

    Duplicate case ids are rejected. Results are sorted by id for reproducibility.
    """
    folder = confine(directory, allowed_root)
    if not folder.is_dir():
        raise TestCaseError(f"test case directory {directory} does not exist")
    files = sorted(folder.glob(CASE_GLOB))
    if len(files) > MAX_CASES:
        raise TestCaseError(f"refusing to load more than {MAX_CASES} test cases")
    loaded: list[LoadedTestCase] = []
    seen: dict[str, str] = {}
    for file in files:
        confine(file, allowed_root)  # rejects symlinks that escape the allowlisted directory
        case = load_test_case_file(file)
        if case.spec.id in seen:
            raise TestCaseError(
                f"{file.name}: duplicate test case id {case.spec.id} (also in {seen[case.spec.id]})"
            )
        seen[case.spec.id] = file.name
        loaded.append(case)
    return sorted(loaded, key=lambda c: c.spec.id)


def corpus_hash(cases: list[LoadedTestCase]) -> str:
    """Fingerprint of the whole corpus (ids and file hashes), recorded in reports for reproducibility."""
    blob = "\n".join(f"{c.spec.id}:{c.spec_hash}" for c in sorted(cases, key=lambda c: c.spec.id))
    return hashlib.sha256(blob.encode()).hexdigest()
