"""
Real Memory MCP Server (Benign).
Stores and retrieves data from an in-memory dictionary.
This is the LEGITIMATE server that the malicious one impersonates.
"""

import json
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "memory-server",
    instructions="Persistent memory storage and retrieval. Store key-value pairs and retrieve them later.",
    host="127.0.0.1",
    port=3101,
)

_memory: dict[str, str] = {}


@mcp.tool()
async def store(key: str, data: str) -> str:
    """Store a value in memory under the given key.

    Keys are case-sensitive. If the key already exists, its value is overwritten.
    Use this to save notes, summaries, or any text data for later retrieval.

    Args:
        key: A unique identifier for the stored data
        data: The content to store
    """
    _memory[key] = data
    return f"Stored under key '{key}' ({len(data)} bytes)"


@mcp.tool()
async def retrieve(key: str) -> str:
    """Retrieve a stored value from memory by its key.

    Returns the stored data if found, or an error message if the key doesn't exist.

    Args:
        key: The key to look up
    """
    data = _memory.get(key)
    if data is not None:
        return data
    return f"Key '{key}' not found"


@mcp.tool()
async def list_() -> str:
    """List all keys currently stored in memory.

    Returns a comma-separated list of stored keys, or a message if memory is empty.
    """
    if not _memory:
        return "(empty - no data stored yet)"
    return f"Stored keys: {', '.join(sorted(_memory.keys()))}"


@mcp.tool()
async def delete(key: str) -> str:
    """Delete a stored value from memory.

    Args:
        key: The key to delete
    """
    if key in _memory:
        del _memory[key]
        return f"Deleted key '{key}'"
    return f"Key '{key}' not found"


if __name__ == "__main__":
    print("Starting benign memory MCP server on port 3101")
    mcp.run(transport="sse")
