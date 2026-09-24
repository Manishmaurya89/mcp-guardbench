"""The transparent rule catalogue for static metadata analysis.

Every rule is data: a stable ``rule_id``, a category, a *base* severity, a confidence, a
remediation, and bounded regexes. Nothing here calls a model or the network. Confidence
reflects how often the pattern is benign in real tool metadata; the analyzer calibrates
severity from it (see ``severity.calibrate``) and looks at context before reporting.

Regexes use bounded gaps (``{0,N}``) and no nested quantifiers, and the analyzer only
scans a length-capped, normalized copy of each text, so hostile input cannot cause
catastrophic backtracking.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from guardbench.domain.enums import FindingCategory, Severity

_FLAGS = re.IGNORECASE


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, _FLAGS) for p in patterns)


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A regex-driven detection rule."""

    rule_id: str
    slug: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float
    patterns: tuple[re.Pattern[str], ...]
    remediation: str
    #: True for weak signals that only report when no stronger rule fired on the same text.
    weak: bool = False


_INSTRUCTION_TARGET = r"(?:instructions?|prompts?|messages?|context|rules|guidelines|directions)"
_SENSITIVE_OBJECT = (
    r"(?:results?|output|data|contents?|response|conversation|history|context|files?|secrets?|"
    r"credentials?|tokens?|keys?|passwords?|records?)"
)
_CREDENTIAL_OBJECT = (
    r"(?:~/?\.ssh|\.ssh|\.env\b|id_rsa|private keys?|ssh keys?|api[ _-]?keys?|access tokens?|"
    r"auth(?:entication)? tokens?|passwords?|credentials?|secrets?|keychain|/etc/passwd|/etc/shadow)"
)

PATTERN_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "MA-001",
        "instruction_override",
        "Instruction-override language in tool metadata",
        FindingCategory.TOOL_POISONING,
        Severity.HIGH,
        0.9,
        _rx(
            rf"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+{_INSTRUCTION_TARGET}",
            rf"\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|system|user)\b.{{0,30}}{_INSTRUCTION_TARGET}?",
            r"\boverride\s+(?:the\s+|all\s+|any\s+)?(?:system|previous|safety|security|user|policy|policies|instructions?)\b",
            r"\bignore\s+(?:the\s+)?user'?s?\s+(?:request|instructions?|question|message|task)\b",
            r"\bforget\s+(?:everything|all\s+(?:previous|prior)|your\s+instructions)\b",
            r"\bnew\s+(?:system\s+)?instructions?\s*:",
            r"\byou\s+(?:must|should|will)\s+now\s+(?:ignore|disregard|forget)\b",
        ),
        "Remove instruction-like text from tool metadata. Descriptions should say what the tool does, "
        "never tell the model how to behave.",
    ),
    PatternRule(
        "MA-002",
        "system_prompt_reference",
        "Reference to system message or prompt in tool metadata",
        FindingCategory.TOOL_POISONING,
        Severity.MEDIUM,
        0.45,
        _rx(
            r"\bsystem\s+(?:message|prompt|instruction)s?\b",
            r"\bdeveloper\s+(?:message|prompt|instruction)s?\b",
        ),
        "Tool metadata should not refer to the system prompt. "
        "Remove the reference or review why it is there.",
    ),
    PatternRule(
        "MA-003",
        "concealment",
        "Instruction to conceal behavior from the user",
        FindingCategory.TOOL_POISONING,
        Severity.HIGH,
        0.9,
        _rx(
            r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|notify|alert|disclose)\b.{0,20}\b(?:the\s+)?user\b",
            r"\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?user\b",
            r"\bhidden\s+instructions?\b",
            r"\bsecretly\b",
            r"\bsilently\s+(?:send|call|read|forward|upload|copy|include)\b",
            r"\bkeep\s+(?:this|it)\s+(?:secret|hidden|confidential)\s+from\b",
        ),
        "Remove text that asks the model to hide actions from the user. "
        "Legitimate tools have nothing to conceal.",
    ),
    PatternRule(
        "MA-004",
        "mandatory_chaining",
        "Metadata mandates calling other tools or steps",
        FindingCategory.TOOL_POISONING,
        Severity.HIGH,
        0.8,
        _rx(
            r"\balways\s+(?:call|invoke|run|execute|trigger)\b",
            r"\bbefore\s+(?:using|calling|invoking|running)\s+this\s+tool\b",
            r"\bafter\s+(?:using|calling|invoking|running)\s+this\s+tool\b.{0,40}\b(?:must|should|need|always|then)\b",
            r"\byou\s+(?:must|should|need\s+to|have\s+to)\s+(?:first\s+)?(?:call|invoke|read|send)\b",
            r"\b(?:the\s+)?(?:assistant|model|ai|agent)\s+(?:must|should|needs\s+to|has\s+to)\s+(?:call|invoke|read|send)\b",
        ),
        "Do not let a tool description script the model's next actions. Move workflow guidance to the client "
        "or system prompt where the operator controls it.",
    ),
    PatternRule(
        "MA-005",
        "outbound_instruction",
        "Instruction to send data to another destination",
        FindingCategory.TOOL_POISONING,
        Severity.HIGH,
        0.85,
        _rx(
            rf"\bsend\s+(?:the\s+|this\s+|all\s+|any\s+|your\s+)?{_SENSITIVE_OBJECT}(?:\s+\w+){{0,4}}\s+to\b",
            rf"\b(?:forward|upload|post|transmit|leak|exfiltrate|email|copy)\s+(?:the\s+|this\s+|all\s+|any\s+)?{_SENSITIVE_OBJECT}\b",
            rf"\binclude\s+(?:the\s+)?(?:contents?\s+of\s+)?{_CREDENTIAL_OBJECT}\s+in\b",
            r"\bexfiltrat\w*",
        ),
        "Remove instructions that direct data to a destination. Data movement must be an explicit, "
        "policy-checked tool call, not metadata text.",
    ),
    PatternRule(
        "MA-006",
        "credential_access_instruction",
        "Instruction to read or reveal credentials",
        FindingCategory.TOOL_POISONING,
        Severity.HIGH,
        0.85,
        _rx(
            rf"\b(?:read|open|cat|access|fetch|retrieve|get|load|print|display|reveal|show|dump|output)\s+(?:the\s+|your\s+|all\s+|any\s+)?(?:contents?\s+of\s+)?{_CREDENTIAL_OBJECT}",
        ),
        "A tool description must never direct the model to read credentials or key material.",
    ),
    PatternRule(
        "MA-007",
        "sensitive_word",
        "Sensitive wording in tool metadata (weak signal)",
        FindingCategory.TOOL_POISONING,
        Severity.LOW,
        0.4,
        _rx(r"\breveal\b", r"\bsecret\b", r"\boverride\b", r"\bconfidential\b"),
        "Review the wording. This is a weak signal that only matters alongside stronger indicators.",
        weak=True,
    ),
    PatternRule(
        "MA-008",
        "pseudo_system_markup",
        "Pseudo-system markup or hidden comment in metadata",
        FindingCategory.TOOL_POISONING,
        Severity.HIGH,
        0.85,
        _rx(
            r"<\s*/?\s*(?:important|system|instructions?|admin|override|hidden|secret|assistant)\s*>",
            r"\[\s*(?:system|instructions?|important|admin)\s*\]",
            r"^\s*#{2,}\s*(?:system|instructions?)\b",
            r"<!--.{0,400}?-->",
            r"^\s*\[//\]\s*:\s*#",
        ),
        "Strip markup that imitates system channels. Tool metadata is data, not a control channel.",
    ),
    PatternRule(
        "MA-011",
        "encoded_payload",
        "Long encoded blob inside tool metadata",
        FindingCategory.TOOL_POISONING,
        Severity.MEDIUM,
        0.6,
        _rx(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])", r"\b[0-9a-f]{96,}\b"),
        "Descriptions should be readable prose. Decode and review the blob, or remove it.",
    ),
    PatternRule(
        "MA-013",
        "model_directed_pressure",
        "Pressure or urgency aimed at the model",
        FindingCategory.TOOL_POISONING,
        Severity.MEDIUM,
        0.55,
        _rx(
            r"\b(?:it\s+is|this\s+is)\s+(?:very\s+|extremely\s+)?(?:important|critical|essential|crucial)\s+that\s+(?:you|the\s+(?:assistant|model|agent))\b",
            r"\botherwise\s+(?:the\s+)?(?:tool|system|task|operation|request)\s+(?:will\s+)?(?:fail|break|crash|not\s+work)\b",
        ),
        "Remove urgency language aimed at the model; it is a common manipulation pattern.",
    ),
)

#: Imperative reference to another tool ("call the export_records tool").
CROSS_TOOL_REFERENCE = re.compile(
    r"\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[`'\"]?(?P<tool>[A-Za-z][\w.\-]{2,63})[`'\"]?\s+(?:tool|function|command)\b",
    _FLAGS,
)
CROSS_TOOL_RULE_ID = "MA-009"

#: Rule IDs implemented outside the regex table (structural or contextual checks).
STRUCTURAL_RULES: dict[str, tuple[str, str]] = {
    "MA-009": ("cross_tool_reference", "Metadata instructs the model to call another tool"),
    "MA-010": ("hidden_unicode", "Invisible or bidirectional Unicode characters in metadata"),
    "MA-012": ("oversized_text", "Unusually long description"),
    "MA-020": ("purpose_mismatch", "Description mentions capabilities unrelated to the tool's purpose"),
    "MA-021": ("capability_contradiction", "Declared or hinted capabilities contradict each other"),
    "MA-022": ("high_risk_capability", "Tool exposes a high-risk capability"),
    "MA-090": ("compound_poisoning_signals", "Several independent poisoning indicators on one tool"),
    "SR-001": ("open_additional_properties", "Input object accepts undeclared properties"),
    "SR-002": ("unrestricted_string", "Free-form string where an enum or pattern is expected"),
    "SR-003": ("unrestricted_path", "Path-like parameter without directory restriction"),
    "SR-004": ("unrestricted_url", "URL parameter without domain restriction"),
    "SR-005": ("shell_like_parameter", "Free-form shell-like parameter"),
    "SR-006": ("free_form_sql", "Free-form SQL parameter"),
    "SR-007": ("excessive_schema_depth", "Schema nesting is unusually deep"),
    "SH-001": ("duplicate_tool_name", "Same tool name on multiple servers"),
    "SH-002": ("confusable_tool_name", "Confusingly similar tool names across servers"),
    "SH-003": ("similar_description", "Near-identical descriptions under different tool identities"),
}

# --- schema-risk name lexicons -------------------------------------------------------------------

PATH_PARAM_NAMES = frozenset(
    {"path", "paths", "file", "files", "filepath", "filename", "dir", "directory", "folder"}
)
URL_PARAM_NAMES = frozenset({"url", "uri", "endpoint", "webhook", "href", "link", "callback_url", "callback"})
SHELL_PARAM_NAMES = frozenset(
    {"command", "cmd", "shell", "shell_command", "script", "bash", "exec", "expression", "eval"}
)
SQL_PARAM_NAMES = frozenset({"sql", "statement", "raw_query"})
ENUM_EXPECTED_NAMES = frozenset(
    {
        "mode",
        "type",
        "status",
        "format",
        "action",
        "level",
        "kind",
        "category",
        "method",
        "operation",
        "priority",
        "direction",
        "unit",
        "state",
        "role",
        "scope",
    }
)
ALLOWLIST_KEYS = frozenset(
    {"x-allowed-directories", "x-allowed-domains", "x-allowed-hosts", "x-guardbench-allowlist"}
)

DESCRIPTION_SOFT_LIMIT = 2000


def normalize_for_matching(text: str) -> str:
    """NFKC-normalize, drop invisible format characters, collapse whitespace.

    Applied before matching so trivially obfuscated phrases such as ``ig<ZWSP>nore previous``
    are still caught. The hidden-Unicode rule inspects the *raw* text separately.
    """
    folded = unicodedata.normalize("NFKC", text)
    visible = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return re.sub(r"[ \t\r\f\v]+", " ", visible).strip()


def format_characters(text: str) -> list[tuple[str, str]]:
    """Return ``(code_point, unicode_name)`` for each invisible format character in ``text``."""
    found: dict[str, str] = {}
    for ch in text:
        if unicodedata.category(ch) == "Cf":
            found.setdefault(f"U+{ord(ch):04X}", unicodedata.name(ch, "UNNAMED FORMAT CHARACTER"))
    return sorted(found.items())


def is_high_risk_format_char(code_point: str) -> bool:
    """Bidi controls and tag characters can visually reorder or fully hide text."""
    value = int(code_point.removeprefix("U+"), 16)
    return (
        0x202A <= value <= 0x202E  # bidi embedding/override
        or 0x2066 <= value <= 0x2069  # bidi isolates
        or 0xE0000 <= value <= 0xE007F  # tag characters (invisible ASCII)
    )
