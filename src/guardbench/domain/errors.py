"""Explicit exception hierarchy. Nothing here is swallowed silently."""

from __future__ import annotations


class GuardBenchError(Exception):
    """Base class for all GuardBench errors."""


class ValidationFailure(GuardBenchError):
    """Input failed validation (test case, policy, request)."""


class TestCaseError(ValidationFailure):
    """A test-case YAML file is malformed or violates the safety contract."""

    __test__ = False  # not a pytest test class


class PathNotAllowedError(ValidationFailure):
    """A path resolved outside an allowlisted directory."""


class UnknownFixtureError(ValidationFailure):
    """A fixture name is not in the static allowlist."""


class PolicyError(GuardBenchError):
    """The policy file is malformed or internally inconsistent."""


class NotFoundError(GuardBenchError):
    """A requested entity does not exist."""


class ConflictError(GuardBenchError):
    """The requested state change conflicts with current state."""


class AdapterError(GuardBenchError):
    """An adapter failed while running a test case."""


class AdapterUnavailableError(AdapterError):
    """An adapter cannot run here (missing tool, not configured). Never faked."""


class FixtureSafetyError(GuardBenchError):
    """A fixture attempted something outside the lab's safety contract."""
