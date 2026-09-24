"""Path confinement. Any path that comes from a user, a request, or a config file goes through here."""

from __future__ import annotations

from pathlib import Path

from guardbench.domain.errors import PathNotAllowedError


def confine(path: str | Path, root: Path) -> Path:
    """Resolve ``path`` (relative to the current directory, like a shell argument) and require it
    to lie inside ``root``.

    Symlinks are resolved *before* the containment check, so a link that points outside ``root``
    is rejected as well. ``..`` segments, absolute paths elsewhere, and NUL bytes are refused.
    Raises :class:`PathNotAllowedError`.
    """
    text = str(path)
    if "\x00" in text:
        raise PathNotAllowedError("path contains a NUL byte")
    resolved_root = root.resolve()
    target = Path(text).resolve()
    if target != resolved_root and resolved_root not in target.parents:
        raise PathNotAllowedError(f"path {text!r} resolves outside the allowed directory {root}")
    return target


def resolve_within(base: Path, name: str | Path) -> Path:
    """Resolve ``name`` *relative to* ``base`` and require the result to stay inside ``base``.

    Use this for a file name inside an allowlisted directory (for example a test-case file name
    supplied through the API). Absolute names are only accepted if they already lie inside ``base``.
    """
    text = str(name)
    if "\x00" in text:
        raise PathNotAllowedError("path contains a NUL byte")
    candidate = Path(text) if Path(text).is_absolute() else base / text
    return confine(candidate, base)
