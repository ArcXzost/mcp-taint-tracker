"""
MCP Interception Layer — Component 1.

Captures MCP tool requests and responses, timestamps them, assigns unique call
and session identifiers, and propagates structured event traces to downstream
analysis engines and trace processors.
"""

import logging
import time
import uuid
from typing import Dict, Any, List, Optional, Callable

from schema import Event

logger = logging.getLogger(__name__)


class MCPInterceptor:
    """
    Intercepts MCP tool calls, records trace events, and forwards them
    to registered trace handlers (e.g., OpenTelemetry / Phoenix).
    """

    def __init__(self, session_id: str = None):
        self.session_id: str = session_id or str(uuid.uuid4())
        self.events: List[Event] = []
        self._trace_handlers: List[Callable[[Event], None]] = []

    def add_trace_handler(self, handler: Callable[[Event], None]) -> None:
        """Register a handler to be notified of intercepted events."""
        self._trace_handlers.append(handler)

    def intercept(
        self,
        tool_name: str,
        server_name: str,
        tool_input: Dict[str, Any],
        tool_output: Dict[str, Any],
    ) -> Event:
        """
        Intercept a tool call request and response, creating an Event trace.

        Raises ValueError if tool_name or server_name are empty/invalid.
        """
        if not tool_name or not isinstance(tool_name, str):
            raise ValueError("tool_name must be a non-empty string")
        if not server_name or not isinstance(server_name, str):
            raise ValueError("server_name must be a non-empty string")

        event = Event(
            call_id=str(uuid.uuid4()),
            session_id=self.session_id,
            tool_name=tool_name,
            server_name=server_name,
            tool_input=tool_input,
            tool_output=tool_output,
            timestamp=time.time(),
        )

        self.events.append(event)
        self._emit_trace(event)

        logger.debug(
            "Intercepted tool call: %s on %s [call_id=%s]",
            tool_name,
            server_name,
            event.call_id[:8],
        )

        return event

    def _emit_trace(self, event: Event) -> None:
        """Emit trace data to logger and registered handlers."""
        # Log the raw event trace as JSON
        logger.info("TRACE EVENT: %s", event.model_dump_json())

        # Forward trace to handlers (e.g. OpenTelemetry, Arize Phoenix)
        for handler in self._trace_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error("Error in trace handler: %s", e)

    def get_session_events(self) -> List[Event]:
        """Retrieve all events captured in this interception session."""
        return self.events

    def get_event_by_id(self, call_id: str) -> Optional[Event]:
        """Retrieve a specific event by its call_id, or None if not found."""
        for event in self.events:
            if event.call_id == call_id:
                return event
        return None

    def clear(self) -> None:
        """Clear all events and reset the interceptor session."""
        self.events.clear()
