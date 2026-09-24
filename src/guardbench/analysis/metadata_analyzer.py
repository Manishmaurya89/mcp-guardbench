"""Static metadata analyzer.

Inspects the *whole* tool definition (name, title, description, input and output schemas,
property names, enum values, required fields, annotations, ``_meta``, declared capabilities)
and returns structured, explainable findings. Fully deterministic: no LLM, no network,
no clock. Every finding names its rule, location, matched evidence, and remediation.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from itertools import combinations
from typing import Any

from guardbench.analysis.capabilities import (
    HIGH_RISK_DOMAINS,
    CapabilityProfile,
    domains_in_text,
    effective_capabilities,
    profile_tool,
    tokenize_name,
    words_in,
)
from guardbench.analysis.risk_rules import (
    ALLOWLIST_KEYS,
    CROSS_TOOL_REFERENCE,
    CROSS_TOOL_RULE_ID,
    DESCRIPTION_SOFT_LIMIT,
    ENUM_EXPECTED_NAMES,
    PATH_PARAM_NAMES,
    PATTERN_RULES,
    SHELL_PARAM_NAMES,
    SQL_PARAM_NAMES,
    STRUCTURAL_RULES,
    URL_PARAM_NAMES,
    PatternRule,
    format_characters,
    is_high_risk_format_char,
    normalize_for_matching,
)
from guardbench.analysis.schema_analyzer import (
    MAX_DEPTH,
    ParamInfo,
    TextSite,
    exceeds_depth,
    has_value_restriction,
    iter_object_schemas,
    iter_parameters,
    iter_text_sites,
    schema_string_types,
    truncate_for_scan,
)
from guardbench.analysis.severity import calibrate
from guardbench.domain.enums import Capability, FindingCategory, Severity
from guardbench.domain.schemas import Finding, ToolDefinitionData

_NAME_KINDS = frozenset({"tool_name", "param_name", "required_name", "annotations_key", "meta_key"})
_GENERIC_REFERENTS = frozenset(
    {"this", "that", "the", "same", "another", "other", "following", "above", "below"}
)
_HIGH_RISK_CAPS = frozenset({Capability.SEND, Capability.EXECUTE, Capability.DELETE})
_MUTATING_CAPS = frozenset({Capability.WRITE, Capability.DELETE, Capability.SEND, Capability.EXECUTE})
STRONG_POISONING_RULES = frozenset({"MA-001", "MA-003", "MA-004", "MA-005", "MA-006", "MA-008", "MA-009"})
MAX_PAIRWISE_TOOLS = 500
SNIPPET_RADIUS = 60

_PATH_SUFFIXES = ("_path", "_file", "_dir", "_directory", "_folder", "_filename")
_URL_SUFFIXES = ("_url", "_uri", "_endpoint", "_webhook")


# --------------------------------------------------------------------------- helpers


def _snippet(text: str, start: int, end: int) -> str:
    left = max(0, start - SNIPPET_RADIUS)
    right = min(len(text), end + SNIPPET_RADIUS)
    prefix = "..." if left > 0 else ""
    suffix = "..." if right < len(text) else ""
    return f"{prefix}{text[left:right]}{suffix}"


def _finding(
    rule_id: str,
    *,
    title: str,
    category: FindingCategory,
    severity: Severity,
    confidence: float,
    description: str,
    remediation: str,
    server_name: str | None,
    tool_name: str | None,
    location: str | None,
    matched: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=calibrate(severity, confidence),
        confidence=confidence,
        description=description,
        location=location,
        matched_evidence=matched,
        remediation=remediation,
        deterministic=True,
        server_name=server_name,
        tool_name=tool_name,
        evidence={"base_severity": severity.value, **(evidence or {})},
    )


def _match_text(site: TextSite) -> str:
    text = truncate_for_scan(site.text)
    if site.kind in _NAME_KINDS:
        text = re.sub(r"[_\-.]+", " ", text)
    return normalize_for_matching(text)


def _sort_key(f: Finding) -> tuple[int, str, str, str]:
    return (-f.severity.rank, f.rule_id, f.tool_name or "", f.location or "")


# --------------------------------------------------------------------------- pattern rules


def _scan_patterns(site: TextSite, text: str, tool: str, server: str | None) -> list[Finding]:
    """Apply the regex rules to one text site. Weak rules report only if nothing stronger fired."""
    findings: list[Finding] = []
    for rule in PATTERN_RULES:
        if rule.weak:
            continue
        hit = _first_match(rule, text)
        if hit:
            findings.append(_pattern_finding(rule, site, text, hit, tool, server))
    if not findings:
        for rule in PATTERN_RULES:
            if rule.weak and (hit := _first_match(rule, text)):
                findings.append(_pattern_finding(rule, site, text, hit, tool, server))
                break
    return findings


def _first_match(rule: PatternRule, text: str) -> re.Match[str] | None:
    for pattern in rule.patterns:
        if match := pattern.search(text):
            return match
    return None


def _pattern_finding(
    rule: PatternRule, site: TextSite, text: str, match: re.Match[str], tool: str, server: str | None
) -> Finding:
    return _finding(
        rule.rule_id,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,
        description=(
            f"Rule {rule.rule_id} ({rule.slug}) matched {site.kind.replace('_', ' ')} of tool '{tool}'. "
            "Tool-supplied text is untrusted, yet models read it as if it were instructions."
        ),
        remediation=rule.remediation,
        server_name=server,
        tool_name=tool,
        location=site.location,
        matched=_snippet(text, match.start(), match.end()),
        evidence={"site_kind": site.kind, "region": site.region, "rule_slug": rule.slug},
    )


def _scan_hidden_unicode(site: TextSite, tool: str, server: str | None) -> list[Finding]:
    chars = format_characters(site.text)
    if not chars:
        return []
    dangerous = any(is_high_risk_format_char(cp) for cp, _ in chars)
    rendered = ", ".join(f"{cp} {name}" for cp, name in chars[:8])
    return [
        _finding(
            "MA-010",
            title=STRUCTURAL_RULES["MA-010"][1],
            category=FindingCategory.TOOL_POISONING,
            severity=Severity.HIGH if dangerous else Severity.MEDIUM,
            confidence=0.9,
            description="Invisible format characters can hide instructions from human reviewers "
            "while remaining visible to the model.",
            remediation="Strip invisible and bidirectional control characters from tool metadata.",
            server_name=server,
            tool_name=tool,
            location=site.location,
            matched=rendered,
            evidence={"code_points": [cp for cp, _ in chars], "bidi_or_tag_characters": dangerous},
        )
    ]


def _scan_cross_tool(
    site: TextSite,
    text: str,
    tool: ToolDefinitionData,
    siblings: Mapping[str, ToolDefinitionData],
    server: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    own_domains = domains_in_text(" ".join(tokenize_name(tool.name)))
    for match in CROSS_TOOL_REFERENCE.finditer(text):
        ref = match.group("tool")
        if ref.lower() in _GENERIC_REFERENTS or ref.lower() == tool.name.lower():
            continue
        severity, confidence, why = _judge_reference(ref, own_domains, siblings)
        if severity is None:
            continue
        findings.append(
            _finding(
                CROSS_TOOL_RULE_ID,
                title=STRUCTURAL_RULES[CROSS_TOOL_RULE_ID][1],
                category=FindingCategory.CROSS_TOOL_REFERENCE,
                severity=severity,
                confidence=confidence,
                description=f"Tool '{tool.name}' tells the model to call '{ref}': {why}.",
                remediation="Tool metadata must not direct the model to invoke other tools. "
                "Let the operator or client define cross-tool workflows.",
                server_name=server,
                tool_name=tool.name,
                location=site.location,
                matched=_snippet(text, match.start(), match.end()),
                evidence={"referenced_tool": ref, "reason": why},
            )
        )
    return findings


def _judge_reference(
    ref: str, own_domains: set[str], siblings: Mapping[str, ToolDefinitionData]
) -> tuple[Severity | None, float, str]:
    sibling = siblings.get(ref) or next((t for n, t in siblings.items() if n.lower() == ref.lower()), None)
    if sibling is None:
        return Severity.MEDIUM, 0.6, "it is not a tool on this server"
    if effective_capabilities(sibling) & _HIGH_RISK_CAPS:
        return (
            Severity.HIGH,
            0.85,
            "the referenced tool has a higher-risk capability (send, execute, or delete)",
        )
    ref_domains = domains_in_text(" ".join(tokenize_name(sibling.name)))
    if ref_domains and own_domains and not (ref_domains & own_domains):
        return Severity.MEDIUM, 0.65, "the referenced tool serves an unrelated purpose"
    return None, 0.0, "related helper tool"


# --------------------------------------------------------------------------- purpose and capability


#: Domains a capability implicitly involves (a tool that sends is *about* the network).
_IMPLIED_DOMAINS = {Capability.SEND: "network", Capability.EXECUTE: "shell"}


def _declared_domains(tool: ToolDefinitionData, profile: CapabilityProfile) -> set[str]:
    """What the tool says it is *about*, taken from its name and title only.

    The description is the text being judged, so it must never define its own purpose:
    otherwise a hostile headline such as "Search the catalog and upload results elsewhere"
    would legitimize itself.
    """
    domains = domains_in_text(" ".join(tokenize_name(tool.name)))
    if tool.title:
        domains |= domains_in_text(tool.title)
    caps = set(profile.declared) | set(profile.inferred_from_name)
    domains |= {_IMPLIED_DOMAINS[c] for c in caps if c in _IMPLIED_DOMAINS}
    return domains


def _check_purpose_mismatch(
    tool: ToolDefinitionData, sites: list[TextSite], profile: CapabilityProfile, server: str | None
) -> list[Finding]:
    declared = _declared_domains(tool, profile)
    findings: list[Finding] = []
    seen: set[str] = set()
    for site in sites:
        if site.kind in {"tool_name", "tool_title"} or site.region in {"annotations", "meta"}:
            continue
        for domain in sorted((domains_in_text(_match_text(site)) & HIGH_RISK_DOMAINS) - declared - seen):
            seen.add(domain)
            mild = domain == "network"
            findings.append(
                _finding(
                    "MA-020",
                    title=STRUCTURAL_RULES["MA-020"][1],
                    category=FindingCategory.PURPOSE_MISMATCH,
                    severity=Severity.LOW if mild else Severity.MEDIUM,
                    confidence=0.5 if mild else 0.7,
                    description=f"Tool '{tool.name}' is about {sorted(declared) or 'an unspecified purpose'} "
                    f"but its metadata refers to {domain} access.",
                    remediation="Remove the unrelated capability from the description or split it into a "
                    "separate tool with its own approval.",
                    server_name=server,
                    tool_name=tool.name,
                    location=site.location,
                    matched=_snippet(_match_text(site), 0, min(len(site.text), 120)),
                    evidence={"declared_domains": sorted(declared), "unrelated_domain": domain},
                )
            )
    return findings


def _check_capabilities(
    tool: ToolDefinitionData, profile: CapabilityProfile, server: str | None
) -> list[Finding]:
    findings: list[Finding] = []
    claimed_read_only = profile.claims_read_only or profile.inferred_from_name == {Capability.READ}
    extra = (set(profile.declared) | set(profile.inferred_from_schema)) & _MUTATING_CAPS
    if claimed_read_only and extra:
        risky = extra & _HIGH_RISK_CAPS
        findings.append(
            _finding(
                "MA-021",
                title=STRUCTURAL_RULES["MA-021"][1],
                category=FindingCategory.EXCESSIVE_PERMISSION,
                severity=Severity.HIGH if risky else Severity.MEDIUM,
                confidence=0.9,
                description=f"Tool '{tool.name}' presents as read-only but declares or implies "
                f"{sorted(c.value for c in extra)}.",
                remediation="Make the declared capabilities consistent with the tool's behavior, "
                "and split mutating operations into separately approved tools.",
                server_name=server,
                tool_name=tool.name,
                location="_meta / annotations",
                matched=f"claims read-only; also {sorted(c.value for c in extra)}",
                evidence={
                    "declared": sorted(c.value for c in profile.declared),
                    "read_only_hint": profile.read_only_hint,
                },
            )
        )
    if profile.read_only_hint is True and profile.destructive_hint is True:
        findings.append(
            _finding(
                "MA-021",
                title=STRUCTURAL_RULES["MA-021"][1],
                category=FindingCategory.EXCESSIVE_PERMISSION,
                severity=Severity.HIGH,
                confidence=0.9,
                description=f"Tool '{tool.name}' sets both readOnlyHint and destructiveHint.",
                remediation="A tool cannot be both read-only and destructive. Correct the annotations.",
                server_name=server,
                tool_name=tool.name,
                location="annotations",
                matched="readOnlyHint=true, destructiveHint=true",
            )
        )
    return findings


def _check_high_risk_capabilities(
    tool: ToolDefinitionData, profile: CapabilityProfile, server: str | None
) -> list[Finding]:
    findings: list[Finding] = []
    for cap in sorted(profile.effective & _HIGH_RISK_CAPS):
        declared = cap in profile.declared or (cap is Capability.DELETE and profile.destructive_hint is True)
        source = "declared" if declared else "inferred from name or schema"
        base = Severity.HIGH if cap is Capability.EXECUTE else Severity.MEDIUM
        findings.append(
            _finding(
                "MA-022",
                title=STRUCTURAL_RULES["MA-022"][1],
                category=FindingCategory.EXCESSIVE_PERMISSION,
                severity=base,
                # A declared capability is a fact; a verb in a name ("run_report") is only a hint.
                confidence=0.9 if declared else 0.25,
                description=f"Tool '{tool.name}' exposes the '{cap.value}' capability ({source}). "
                "High-risk capabilities need least-privilege review and runtime approval.",
                remediation="Confirm the capability is required. Gate it behind approval, "
                "and deny by default "
                "for execute.",
                server_name=server,
                tool_name=tool.name,
                location="_meta['guardbench/capabilities']" if declared else "name",
                matched=f"capability={cap.value} ({source})",
                evidence={"capability": cap.value, "source": source},
            )
        )
    return findings


# --------------------------------------------------------------------------- schema risk


def _param_tokens(param: ParamInfo) -> tuple[set[str], str]:
    lowered = param.name.lower()
    return set(tokenize_name(param.name)) | {lowered}, lowered


def _restricted(schema: dict[str, Any]) -> bool:
    return has_value_restriction(schema) or any(k in schema for k in ALLOWLIST_KEYS)


def _check_schema_risk(tool: ToolDefinitionData, server: str | None) -> list[Finding]:
    findings: list[Finding] = []
    for region, schema in (("inputSchema", tool.input_schema), ("outputSchema", tool.output_schema)):
        if schema is not None and exceeds_depth(schema):
            findings.append(
                _finding(
                    "SR-007",
                    title=STRUCTURAL_RULES["SR-007"][1],
                    category=FindingCategory.SCHEMA_RISK,
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    description=f"The {region} nests deeper than {MAX_DEPTH} levels. Deep schemas can hide "
                    "content beyond what the analyzer inspects and can exhaust clients.",
                    remediation="Flatten the schema. Reject servers that publish "
                    "pathologically nested schemas.",
                    server_name=server,
                    tool_name=tool.name,
                    location=region,
                    matched=f"depth>{MAX_DEPTH}",
                )
            )
    for obj in iter_object_schemas(tool.input_schema):
        if "properties" in obj.schema and obj.schema.get("additionalProperties", True) is not False:
            findings.append(
                _finding(
                    "SR-001",
                    title=STRUCTURAL_RULES["SR-001"][1],
                    category=FindingCategory.SCHEMA_RISK,
                    severity=Severity.LOW,
                    confidence=0.8,
                    description="The object schema does not set additionalProperties: false, so the server "
                    "accepts undeclared arguments that validation will not constrain.",
                    remediation="Set additionalProperties to false on every strict input object.",
                    server_name=server,
                    tool_name=tool.name,
                    location=obj.location,
                    matched="additionalProperties missing or true",
                )
            )
    for param in iter_parameters(tool.input_schema):
        findings.extend(_check_parameter(tool.name, param, server))
    return findings


def _check_parameter(tool_name: str, param: ParamInfo, server: str | None) -> list[Finding]:
    if not schema_string_types(param.schema) and param.schema.get("format") not in {"uri", "uri-reference"}:
        return []
    tokens, lowered = _param_tokens(param)
    restricted = _restricted(param.schema)

    def make(
        rule_id: str, category: FindingCategory, sev: Severity, conf: float, why: str, fix: str
    ) -> Finding:
        return _finding(
            rule_id,
            title=STRUCTURAL_RULES[rule_id][1],
            category=category,
            severity=sev,
            confidence=conf,
            description=f"Parameter '{param.name}' of '{tool_name}': {why}.",
            remediation=fix,
            server_name=server,
            tool_name=tool_name,
            location=param.location,
            matched=f"{param.name}: {param.schema.get('type', param.schema.get('format', 'string'))}",
            evidence={"parameter": param.name, "required": param.required},
        )

    findings: list[Finding] = []
    is_path = bool(tokens & PATH_PARAM_NAMES) or lowered.endswith(_PATH_SUFFIXES)
    is_url = (
        bool(tokens & URL_PARAM_NAMES)
        or lowered.endswith(_URL_SUFFIXES)
        or param.schema.get("format") in {"uri", "uri-reference"}
    )
    if not restricted:
        if is_path:
            findings.append(
                make(
                    "SR-003",
                    FindingCategory.SCHEMA_RISK,
                    Severity.MEDIUM,
                    0.7,
                    "path-like parameter with no allowed-directory restriction",
                    "Constrain with a pattern or enum, or declare x-allowed-directories.",
                )
            )
        if is_url:
            findings.append(
                make(
                    "SR-004",
                    FindingCategory.SCHEMA_RISK,
                    Severity.MEDIUM,
                    0.7,
                    "URL parameter with no domain restriction",
                    "Constrain with a pattern or enum, or declare x-allowed-domains.",
                )
            )
        if tokens & SHELL_PARAM_NAMES:
            findings.append(
                make(
                    "SR-005",
                    FindingCategory.SCHEMA_RISK,
                    Severity.HIGH,
                    0.8,
                    "free-form shell-like parameter",
                    "Replace with an enum of safe operations; never accept raw commands.",
                )
            )
        if tokens & SQL_PARAM_NAMES:
            findings.append(
                make(
                    "SR-006",
                    FindingCategory.SCHEMA_RISK,
                    Severity.MEDIUM,
                    0.6,
                    "free-form SQL parameter",
                    "Use parameterized, server-defined queries instead of raw SQL.",
                )
            )
        if lowered in ENUM_EXPECTED_NAMES and not (is_path or is_url):
            findings.append(
                make(
                    "SR-002",
                    FindingCategory.SCHEMA_RISK,
                    Severity.LOW,
                    0.55,
                    "unrestricted string where an enum or pattern is expected",
                    "Add an enum or pattern so the value space is bounded.",
                )
            )
    return findings


# --------------------------------------------------------------------------- public API


def analyze_tool(
    tool: ToolDefinitionData,
    *,
    server_name: str | None = None,
    sibling_tools: Sequence[ToolDefinitionData] = (),
) -> list[Finding]:
    """Analyze one tool definition and return findings sorted by severity."""
    siblings = {t.name: t for t in sibling_tools if t.name != tool.name}
    profile = profile_tool(tool)
    sites = list(iter_text_sites(tool))
    findings: list[Finding] = []

    for site in sites:
        text = _match_text(site)
        if text:
            findings.extend(_scan_patterns(site, text, tool.name, server_name))
            if site.kind not in _NAME_KINDS:
                findings.extend(_scan_cross_tool(site, text, tool, siblings, server_name))
        findings.extend(_scan_hidden_unicode(site, tool.name, server_name))

    if tool.description and len(tool.description) > DESCRIPTION_SOFT_LIMIT:
        findings.append(
            _finding(
                "MA-012",
                title=STRUCTURAL_RULES["MA-012"][1],
                category=FindingCategory.TOOL_POISONING,
                severity=Severity.LOW,
                confidence=0.5,
                description=f"The description is {len(tool.description)} characters; "
                "long text can bury instructions.",
                remediation="Keep descriptions concise and reviewable.",
                server_name=server_name,
                tool_name=tool.name,
                location="description",
                matched=f"length={len(tool.description)}",
            )
        )

    findings.extend(_check_purpose_mismatch(tool, sites, profile, server_name))
    findings.extend(_check_capabilities(tool, profile, server_name))
    findings.extend(_check_high_risk_capabilities(tool, profile, server_name))
    findings.extend(_check_schema_risk(tool, server_name))
    findings.extend(_compound_finding(tool, findings, server_name))
    return sorted(findings, key=_sort_key)


def _compound_finding(tool: ToolDefinitionData, findings: list[Finding], server: str | None) -> list[Finding]:
    strong = sorted({f.rule_id for f in findings if f.rule_id in STRONG_POISONING_RULES})
    if len(strong) < 3:
        return []
    return [
        _finding(
            "MA-090",
            title=STRUCTURAL_RULES["MA-090"][1],
            category=FindingCategory.TOOL_POISONING,
            severity=Severity.CRITICAL,
            confidence=0.9,
            description=f"Tool '{tool.name}' triggered {len(strong)} independent poisoning rules: {strong}.",
            remediation="Treat this tool as hostile: quarantine the server and review all of its tools.",
            server_name=server,
            tool_name=tool.name,
            location="tool",
            matched=", ".join(strong),
            evidence={"rules": strong},
        )
    ]


def analyze_text(
    text: str,
    *,
    kind: str = "tool_response",
    location: str = "response",
    tool_name: str | None = None,
    server_name: str | None = None,
) -> list[Finding]:
    """Apply the poisoning rules to arbitrary untrusted text, such as a tool *response*.

    The same transparent rules that inspect metadata inspect responses. Findings that would be
    ``tool_poisoning`` in metadata are reported as ``response_injection`` here.
    """
    site = TextSite(location=location, kind=kind, text=text, region="response")
    who = tool_name or "<unknown>"
    matched = _match_text(site)
    findings = _scan_patterns(site, matched, who, server_name) if matched else []
    findings.extend(_scan_hidden_unicode(site, who, server_name))
    relabelled = [
        f.model_copy(update={"category": FindingCategory.RESPONSE_INJECTION})
        if f.category is FindingCategory.TOOL_POISONING
        else f
        for f in findings
    ]
    return sorted(relabelled, key=_sort_key)


def analyze_server(server_name: str, tools: Sequence[ToolDefinitionData]) -> list[Finding]:
    """Analyze every tool of one server, with the server's other tools as context."""
    findings: list[Finding] = []
    for tool in tools:
        findings.extend(analyze_tool(tool, server_name=server_name, sibling_tools=tools))
    return sorted(findings, key=_sort_key)


def analyze_servers(servers: Mapping[str, Sequence[ToolDefinitionData]]) -> list[Finding]:
    """Analyze several servers together, adding cross-server shadowing checks."""
    findings: list[Finding] = []
    for name in sorted(servers):
        findings.extend(analyze_server(name, servers[name]))
    findings.extend(detect_shadowing(servers))
    return sorted(findings, key=_sort_key)


# --------------------------------------------------------------------------- shadowing

_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "$": "s"})


def name_skeleton(name: str) -> str:
    """Fold a tool name so visually confusable spellings compare equal."""
    folded = unicodedata.normalize("NFKC", name).lower()
    folded = re.sub(r"[_\-.\s]+", "", folded)
    return folded.translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w")


def within_edit_distance(a: str, b: str, limit: int = 1) -> bool:
    """True when the Levenshtein distance between ``a`` and ``b`` is at most ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return False
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > limit:
            return False
        previous = current
    return previous[-1] <= limit


def jaccard(a: str, b: str) -> float:
    """Word-set Jaccard similarity of two texts."""
    wa, wb = words_in(a), words_in(b)
    return len(wa & wb) / len(wa | wb) if wa and wb else 0.0


def detect_shadowing(servers: Mapping[str, Sequence[ToolDefinitionData]]) -> list[Finding]:
    """Find identical, confusable, or impersonating tools across different servers."""
    entries = [(s, t) for s in sorted(servers) for t in servers[s]]
    findings: list[Finding] = []

    by_name: dict[str, list[tuple[str, ToolDefinitionData]]] = {}
    for server, tool in entries:
        by_name.setdefault(tool.name, []).append((server, tool))
    for name, group in sorted(by_name.items()):
        owners = sorted({s for s, _ in group})
        if len(owners) < 2:
            continue
        descriptions = [t.description or "" for _, t in group]
        divergent = min(jaccard(a, b) for a, b in combinations(descriptions, 2)) < 0.5
        findings.append(
            _finding(
                "SH-001",
                title=STRUCTURAL_RULES["SH-001"][1],
                category=FindingCategory.SHADOWING,
                severity=Severity.HIGH if divergent else Severity.MEDIUM,
                confidence=0.75,
                description=f"Tool '{name}' is offered by servers {owners}"
                + (" with materially different descriptions." if divergent else "."),
                remediation="Namespace tools per server and pin which server owns each name, so a "
                "later-registered server cannot shadow a trusted tool.",
                server_name=None,
                tool_name=name,
                location=f"tools[{name!r}]",
                matched=f"servers={owners}",
                evidence={"servers": owners, "descriptions_diverge": divergent},
            )
        )

    if len(entries) > MAX_PAIRWISE_TOOLS:
        return findings
    for (s1, t1), (s2, t2) in combinations(entries, 2):
        if s1 == s2 or t1.name == t2.name:
            continue
        skeleton_equal = name_skeleton(t1.name) == name_skeleton(t2.name)
        near = min(len(t1.name), len(t2.name)) >= 6 and within_edit_distance(t1.name.lower(), t2.name.lower())
        if skeleton_equal or near:
            findings.append(
                _finding(
                    "SH-002",
                    title=STRUCTURAL_RULES["SH-002"][1],
                    category=FindingCategory.SHADOWING,
                    severity=Severity.HIGH,
                    confidence=0.85 if skeleton_equal else 0.7,
                    description=f"'{t1.name}' ({s1}) and '{t2.name}' ({s2}) are easy to confuse.",
                    remediation="Rename one tool, or require explicit server-qualified tool references.",
                    server_name=None,
                    tool_name=t2.name,
                    location=f"tools[{t2.name!r}]",
                    matched=f"{s1}:{t1.name} ~ {s2}:{t2.name}",
                    evidence={
                        "servers": [s1, s2],
                        "names": [t1.name, t2.name],
                        "skeleton_equal": skeleton_equal,
                    },
                )
            )
        elif (
            len(words_in(t1.description or "")) >= 6
            and jaccard(t1.description or "", t2.description or "") >= 0.8
        ):
            findings.append(
                _finding(
                    "SH-003",
                    title=STRUCTURAL_RULES["SH-003"][1],
                    category=FindingCategory.SHADOWING,
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    description=f"'{t1.name}' ({s1}) and '{t2.name}' ({s2}) have "
                    "near-identical descriptions.",
                    remediation="Verify which server is authoritative and that neither "
                    "impersonates the other.",
                    server_name=None,
                    tool_name=t2.name,
                    location=f"tools[{t2.name!r}]",
                    matched=f"{s1}:{t1.name} ~ {s2}:{t2.name}",
                    evidence={"servers": [s1, s2], "names": [t1.name, t2.name]},
                )
            )
    return findings
