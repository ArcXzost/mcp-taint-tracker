"""
Taint Source Engine — Component 3.

Identifies sensitive data origins (sources) and dangerous destinations (sinks)
within the MCP tool invocation lifecycle, supporting both exact matches
and regex pattern-based matching.
"""

import re
from typing import List, Dict, Set, Pattern, Tuple

# Exact tool-to-taint label mappings for sensitive sources.
SOURCE_CATEGORIES: Dict[str, str] = {
    "filesystem_read": "filesystem",
    "database_query": "database",
    "get_credentials": "credential",
    "email_read": "email",
    "memory_read": "memory",
    "github_issue_read": "user_input",
    "external_data": "user_input",
}

# Exact tool-to-sink label mappings for dangerous destinations.
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

# Neutral tools that process or transform data but do not act as endpoints.
NEUTRAL_TOOLS: Set[str] = {
    "summarizer",
    "llm_summarize",
    "agent_reasoning",
    "local_report",
    "memory_write",
}

# Pattern-based matching rules for source detection (compiled regex -> label)
SOURCE_PATTERNS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r'.*_read$'), "data_access"),
    (re.compile(r'.*_query$'), "data_access"),
    (re.compile(r'^get_.*'), "data_access"),
]

# Pattern-based matching rules for sink detection (compiled regex -> label)
SINK_PATTERNS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r'.*_send$'), "outbound"),
    (re.compile(r'.*_post$'), "outbound"),
    (re.compile(r'.*_write$'), "data_modification"),
    (re.compile(r'^send_.*'), "outbound"),
]


class TaintSourceEngine:
    """
    Categorizes MCP tools as sensitive sources, dangerous sinks, or neutral nodes.
    Supports dynamic registration and pattern-based classification.
    """

    @staticmethod
    def get_sources(tool_name: str) -> List[str]:
        """
        Determine the source taint labels for a tool name.
        Checks exact matches first, then falls back to regex pattern rules.
        """
        if tool_name in SOURCE_CATEGORIES:
            return [SOURCE_CATEGORIES[tool_name]]

        # Fallback to regex pattern matching
        labels = []
        for pattern, label in SOURCE_PATTERNS:
            if pattern.match(tool_name):
                labels.append(label)
        return labels

    @staticmethod
    def get_sinks(tool_name: str) -> List[str]:
        """
        Determine the sink labels for a tool name.
        Checks exact matches first, then falls back to regex pattern rules.
        """
        if tool_name in SINK_CATEGORIES:
            return [SINK_CATEGORIES[tool_name]]

        # Fallback to regex pattern matching
        labels = []
        for pattern, label in SINK_PATTERNS:
            if pattern.match(tool_name):
                labels.append(label)
        return labels

    @staticmethod
    def is_neutral(tool_name: str) -> bool:
        """Check if a tool is registered as a neutral processing tool."""
        return tool_name in NEUTRAL_TOOLS

    @staticmethod
    def register_source(tool_name: str, label: str) -> None:
        """Register a new source tool and its corresponding taint label."""
        SOURCE_CATEGORIES[tool_name] = label

    @staticmethod
    def register_sink(tool_name: str, label: str) -> None:
        """Register a new sink tool and its corresponding sink label."""
        SINK_CATEGORIES[tool_name] = label

    @staticmethod
    def register_neutral(tool_name: str) -> None:
        """Register a tool name as neutral."""
        NEUTRAL_TOOLS.add(tool_name)
