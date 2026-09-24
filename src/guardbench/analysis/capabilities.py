"""Capability inference: what a tool can *do*, versus what it *says* it does.

Servers declare capabilities in ``_meta`` and hint at them via MCP annotations, but both
are self-reported. We also infer capabilities from the tool name and schema. The policy
engine enforces least privilege by using the union (the most restrictive reading).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guardbench.analysis.schema_analyzer import iter_parameters
from guardbench.domain.enums import Capability
from guardbench.domain.schemas import ToolDefinitionData

_VERBS: dict[Capability, frozenset[str]] = {
    Capability.READ: frozenset(
        {
            "get",
            "list",
            "read",
            "search",
            "find",
            "fetch",
            "query",
            "show",
            "view",
            "lookup",
            "describe",
            "count",
        }
    ),
    Capability.WRITE: frozenset(
        {
            "create",
            "add",
            "update",
            "set",
            "write",
            "save",
            "insert",
            "put",
            "patch",
            "modify",
            "edit",
            "append",
        }
    ),
    Capability.DELETE: frozenset(
        {"delete", "remove", "drop", "destroy", "purge", "erase", "clear", "truncate", "wipe", "revoke"}
    ),
    Capability.SEND: frozenset(
        {
            "send",
            "post",
            "publish",
            "notify",
            "email",
            "mail",
            "forward",
            "export",
            "transmit",
            "share",
            "webhook",
            "broadcast",
            "upload",
        }
    ),
    Capability.EXECUTE: frozenset(
        {"exec", "execute", "run", "eval", "shell", "spawn", "launch", "command", "cmd", "script", "deploy"}
    ),
}

_PARAM_HINTS: dict[Capability, frozenset[str]] = {
    Capability.EXECUTE: frozenset({"command", "cmd", "shell", "script", "code", "exec", "expression"}),
    Capability.SEND: frozenset(
        {"webhook", "recipient", "recipients", "destination", "endpoint", "callback_url"}
    ),
}

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

#: Purpose domains. A tool's name and headline place it in one of these.
DOMAIN_KEYWORDS: dict[str, frozenset[str]] = {
    "calendar": frozenset(
        {"calendar", "event", "events", "meeting", "meetings", "schedule", "appointment", "agenda"}
    ),
    "catalog": frozenset({"catalog", "catalogue", "product", "products", "inventory", "item", "items"}),
    "file": frozenset(
        {"file", "files", "directory", "directories", "folder", "folders", "filesystem", "disk"}
    ),
    "network": frozenset(
        {"http", "https", "url", "urls", "webhook", "email", "smtp", "socket", "network", "internet"}
    ),
    "shell": frozenset({"shell", "bash", "terminal", "subprocess", "sudo", "powershell"}),
    # Only unambiguous words: "secret" (secret santa) and "token" (NLP token) are too common in
    # benign text. Explicit credential *instructions* are caught precisely by rule MA-006.
    "credentials": frozenset(
        {"password", "passwords", "passphrase", "credential", "credentials", "keychain"}
    ),
    "database": frozenset({"sql", "database", "table", "tables"}),
}
#: Domains that a benign business tool should not touch unless it is *about* them.
HIGH_RISK_DOMAINS = frozenset({"file", "network", "shell", "credentials"})

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")


def tokenize_name(name: str) -> list[str]:
    """Split ``createCalendarEvent`` / ``create_calendar-event`` into lowercase words."""
    spaced = _CAMEL_RE.sub("_", name)
    return [t.lower() for t in _SPLIT_RE.split(spaced) if t]


def words_in(text: str) -> set[str]:
    """Lowercase alphanumeric words in ``text``."""
    return {w.lower() for w in _WORD_RE.findall(text)}


def domains_in_text(text: str) -> set[str]:
    """Purpose domains whose keywords appear as whole words in ``text``."""
    words = words_in(text)
    return {domain for domain, keywords in DOMAIN_KEYWORDS.items() if words & keywords}


def infer_from_name(name: str) -> set[Capability]:
    """Capabilities implied by the verbs in a tool name (leading verb weighted like any other)."""
    tokens = set(tokenize_name(name))
    return {cap for cap, verbs in _VERBS.items() if tokens & verbs}


def infer_from_schema(tool: ToolDefinitionData) -> set[Capability]:
    """Capabilities implied by parameter names such as ``command`` or ``webhook``."""
    found: set[Capability] = set()
    for param in iter_parameters(tool.input_schema):
        tokens = set(tokenize_name(param.name)) | {param.name.lower()}
        for cap, hints in _PARAM_HINTS.items():
            if tokens & hints:
                found.add(cap)
    return found


@dataclass(frozen=True, slots=True)
class CapabilityProfile:
    """Everything known about a tool's capabilities, and where each fact came from."""

    declared: frozenset[Capability]
    inferred_from_name: frozenset[Capability]
    inferred_from_schema: frozenset[Capability]
    read_only_hint: bool | None
    destructive_hint: bool | None
    open_world_hint: bool | None
    notes: list[str] = field(default_factory=list)

    @property
    def inferred(self) -> frozenset[Capability]:
        """Union of name- and schema-inferred capabilities."""
        return self.inferred_from_name | self.inferred_from_schema

    @property
    def effective(self) -> frozenset[Capability]:
        """Most restrictive reading: declared, inferred, and destructive-hint capabilities together."""
        caps = set(self.declared) | set(self.inferred)
        if self.destructive_hint:
            caps.add(Capability.DELETE)
        return frozenset(caps)

    @property
    def claims_read_only(self) -> bool:
        """The tool presents itself as read-only (hint set, or declared exactly ``read``)."""
        return self.read_only_hint is True or (self.declared == {Capability.READ})

    @property
    def is_known(self) -> bool:
        """Whether any capability at all could be established."""
        return bool(self.effective)


def _bool_or_none(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def profile_tool(tool: ToolDefinitionData) -> CapabilityProfile:
    """Build the capability profile for ``tool``."""
    return CapabilityProfile(
        declared=frozenset(tool.declared_capabilities),
        inferred_from_name=frozenset(infer_from_name(tool.name)),
        inferred_from_schema=frozenset(infer_from_schema(tool)),
        read_only_hint=_bool_or_none(tool.annotations.get("readOnlyHint")),
        destructive_hint=_bool_or_none(tool.annotations.get("destructiveHint")),
        open_world_hint=_bool_or_none(tool.annotations.get("openWorldHint")),
    )


def effective_capabilities(tool: ToolDefinitionData) -> frozenset[Capability]:
    """Least-privilege capability set for ``tool``. Empty means unknown, so callers must be strict."""
    return profile_tool(tool).effective
