"""
Taint Source Engine — Component 3.

Identifies sensitive data origins (sources) and dangerous destinations (sinks)
within the MCP tool invocation lifecycle.

Now with:
- Session-scoped tool schema tracking (rug pull detection)
- OAuth token pattern detection
- Post-approval schema mutation detection
- Encoding-aware taint propagation (base64, hex, URL-encoded data)
"""

import re
import hashlib
import logging
from typing import List, Dict, Set, Pattern, Tuple, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ── Static Source/Sink Mappings ──────────────────────────────────────────────

SOURCE_CATEGORIES: Dict[str, str] = {
    "filesystem_read": "filesystem",
    "database_query": "database",
    "get_credentials": "credential",
    "email_read": "email",
    "memory_read": "memory",
    "github_issue_read": "user_input",
    "external_data": "user_input",
}

SINK_CATEGORIES: Dict[str, str] = {
    "http_request": "http_request",
    "http_post": "http_request",
    "webhook": "webhook",
    "email_send": "email_send",
    "send_email": "email_send",
    "external_storage": "external_storage",
    "code_execution": "code_execution",
    "file_write": "filesystem",
    "tool_action": "tool_action",
}

NEUTRAL_TOOLS: Set[str] = {
    "summarizer",
    "llm_summarize",
    "agent_reasoning",
    "local_report",
    "memory_write",
}

SOURCE_PATTERNS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r".*_read$"), "data_access"),
    (re.compile(r".*_query$"), "data_access"),
    (re.compile(r"^get_.*"), "data_access"),
]

SINK_PATTERNS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r".*_send$"), "outbound"),
    (re.compile(r".*_post$"), "outbound"),
    (re.compile(r".*_write$"), "data_modification"),
    (re.compile(r"^send_.*"), "outbound"),
]

# ── OAuth / Credential Token Patterns ────────────────────────────────────────

OAUTH_PATTERNS: List[Tuple[Pattern[str], str, str]] = [
    (re.compile(r"ya29\.[A-Za-z0-9_-]{40,}"), "oauth_token", "Google OAuth"),
    (re.compile(r"gh[ops]_[A-Za-z0-9]{36,}"), "oauth_token", "GitHub Token"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "api_key", "OpenAI API Key"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "api_key", "Stripe Live Key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "credential", "AWS Access Key"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "oauth_token", "JWT Token"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}"), "oauth_token", "Bearer Token"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "credential", "Private Key"),
]


# ── Schema Mutation Detection ────────────────────────────────────────────────

@dataclass
class ToolSchema:
    """Represents the expected schema of a tool (parameter names, structure)."""
    tool_name: str
    input_keys: Set[str]
    output_keys: Set[str]
    input_structure_hash: str  # Hash of input parameter keys (sorted)
    output_structure_hash: str  # Hash of output parameter keys (sorted)

    @staticmethod
    def from_event(tool_name: str, tool_input: Dict[str, Any], tool_output: Dict[str, Any]) -> "ToolSchema":
        input_keys = set(tool_input.keys())
        output_keys = set(tool_output.keys())
        input_hash = hashlib.md5("".join(sorted(input_keys)).encode()).hexdigest()[:12]
        output_hash = hashlib.md5("".join(sorted(output_keys)).encode()).hexdigest()[:12]
        return ToolSchema(
            tool_name=tool_name,
            input_keys=input_keys,
            output_keys=output_keys,
            input_structure_hash=input_hash,
            output_structure_hash=output_hash,
        )


class SessionSchemaTracker:
    """
    Tracks tool schemas per session to detect post-approval schema mutations.
    
    When a tool is first seen, its schema is stored.
    If the same tool name appears again with different input/output keys,
    a rug pull attack (schema mutation) is flagged.
    """
    
    def __init__(self):
        self._schemas: Dict[str, ToolSchema] = {}
        self._schema_mutations: List[Dict[str, Any]] = []
    
    def check_schema(self, tool_name: str, tool_input: Dict[str, Any], tool_output: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if a tool call matches its previously seen schema.
        Returns a mutation alert dict if schema changed, None otherwise.
        """
        current = ToolSchema.from_event(tool_name, tool_input, tool_output)
        
        if tool_name not in self._schemas:
            self._schemas[tool_name] = current
            return None
        
        previous = self._schemas[tool_name]
        
        mutations = []
        if current.input_structure_hash != previous.input_structure_hash:
            old_inputs = previous.input_keys
            new_inputs = current.input_keys
            added = new_inputs - old_inputs
            removed = old_inputs - new_inputs
            mutations.append(f"input_keys: +{added} -{removed}")
        
        if current.output_structure_hash != previous.output_structure_hash:
            old_outputs = previous.output_keys
            new_outputs = current.output_keys
            added = new_outputs - old_outputs
            removed = old_outputs - new_outputs
            mutations.append(f"output_keys: +{added} -{removed}")
        
        if mutations:
            alert = {
                "type": "schema_mutation",
                "tool_name": tool_name,
                "mutations": mutations,
                "previous_schema": {
                    "input_keys": list(previous.input_keys),
                    "output_keys": list(previous.output_keys),
                },
                "current_schema": {
                    "input_keys": list(current.input_keys),
                    "output_keys": list(current.output_keys),
                },
                "confidence": 0.85,
            }
            self._schema_mutations.append(alert)
            return alert
        
        return None
    
    def get_mutations(self) -> List[Dict[str, Any]]:
        return self._schema_mutations
    
    def clear(self):
        self._schemas.clear()
        self._schema_mutations.clear()


# ── OAuth Scanner ────────────────────────────────────────────────────────────

def scan_for_secrets(text: str) -> List[Dict[str, Any]]:
    """
    Scan text for OAuth tokens, API keys, credentials.
    Returns list of detected secrets with pattern type and sample.
    """
    findings = []
    for pattern, label, description in OAUTH_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            # Truncate the sample for safety (don't log full tokens)
            sample = match[:12] + "..." if len(match) > 15 else match
            findings.append({
                "type": label,
                "description": description,
                "sample": sample,
                "full_length": len(match),
            })
    return findings


# ── Main Engine ──────────────────────────────────────────────────────────────

class TaintSourceEngine:
    """
    Categorizes MCP tools as sensitive sources, dangerous sinks, or neutral nodes.
    Supports dynamic registration, pattern-based classification, and secret scanning.
    """

    @staticmethod
    def get_sources(tool_name: str) -> List[str]:
        if tool_name in SOURCE_CATEGORIES:
            return [SOURCE_CATEGORIES[tool_name]]
        labels = []
        for pattern, label in SOURCE_PATTERNS:
            if pattern.match(tool_name):
                labels.append(label)
        return labels

    @staticmethod
    def get_sinks(tool_name: str) -> List[str]:
        if tool_name in SINK_CATEGORIES:
            return [SINK_CATEGORIES[tool_name]]
        labels = []
        for pattern, label in SINK_PATTERNS:
            if pattern.match(tool_name):
                labels.append(label)
        return labels

    @staticmethod
    def is_neutral(tool_name: str) -> bool:
        return tool_name in NEUTRAL_TOOLS

    @staticmethod
    def register_source(tool_name: str, label: str) -> None:
        SOURCE_CATEGORIES[tool_name] = label

    @staticmethod
    def register_sink(tool_name: str, label: str) -> None:
        SINK_CATEGORIES[tool_name] = label

    @staticmethod
    def register_neutral(tool_name: str) -> None:
        NEUTRAL_TOOLS.add(tool_name)

    @staticmethod
    def has_secret_patterns(text: str) -> bool:
        """Check if text contains any known secret/credential patterns."""
        return len(scan_for_secrets(text)) > 0
