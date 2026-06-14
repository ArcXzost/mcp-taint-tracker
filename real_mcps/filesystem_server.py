"""
Real Filesystem MCP Server.
Actually reads/writes files on the local filesystem.
Uses a configured allowed directory for safety.
"""

import os
import json
import shutil

from mcp.server.fastmcp import FastMCP

ALLOWED_DIR = os.environ.get("MCP_FS_ROOT", os.path.expanduser("~/mcp-workspace"))

mcp = FastMCP(
    "filesystem-server",
    instructions="Filesystem read, write, and list operations. All paths must be within the allowed directory.",
    host="127.0.0.1",
    port=3100,
)


def _resolve_path(user_path: str) -> str:
    """Resolve a user-provided path to an absolute path, checking it's within ALLOWED_DIR."""
    base = os.path.abspath(ALLOWED_DIR)
    target = os.path.abspath(os.path.join(base, user_path))
    if not target.startswith(base + os.sep) and target != base:
        raise PermissionError(f"Path '{user_path}' is outside the allowed directory")
    return target


@mcp.tool()
async def filesystem_read(path: str) -> str:
    """Read the contents of a file at the specified path.

    Args:
        path: Relative or absolute path to the file (must be within allowed directory)
    """
    full_path = _resolve_path(path)
    if not os.path.isfile(full_path):
        return f"Error: '{path}' is not a file or does not exist"
    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


@mcp.tool()
async def filesystem_write(path: str, content: str) -> str:
    """Write content to a file at the specified path. Creates parent directories if needed.

    Args:
        path: Relative or absolute path to the file
        content: Text content to write
    """
    full_path = _resolve_path(path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Written {len(content)} bytes to '{path}'"


@mcp.tool()
async def filesystem_list(path: str = ".") -> str:
    """List files and directories at the specified path.

    Args:
        path: Directory path to list (default: root of allowed directory)
    """
    full_path = _resolve_path(path)
    if not os.path.isdir(full_path):
        return f"Error: '{path}' is not a directory"
    entries = os.listdir(full_path)
    result = []
    for entry in sorted(entries):
        entry_path = os.path.join(full_path, entry)
        suffix = "/" if os.path.isdir(entry_path) else ""
        size = os.path.getsize(entry_path) if os.path.isfile(entry_path) else 0
        result.append(f"{entry}{suffix} ({size} bytes)" if suffix else entry)
    return "\n".join(result) if result else "(empty directory)"


@mcp.tool()
async def filesystem_search(pattern: str, path: str = ".") -> str:
    """Search for files matching a glob pattern.

    Args:
        pattern: Glob pattern (e.g., '*.txt', '**/*.py')
        path: Starting directory
    """
    import glob as glob_mod
    full_path = _resolve_path(path)
    matches = glob_mod.glob(os.path.join(full_path, pattern), recursive=True)
    result = []
    for m in sorted(matches):
        rel = os.path.relpath(m, ALLOWED_DIR)
        result.append(rel)
    return "\n".join(result) if result else "(no matches)"


if __name__ == "__main__":
    os.makedirs(ALLOWED_DIR, exist_ok=True)
    print(f"Starting filesystem MCP server on port 3100")
    print(f"Allowed directory: {ALLOWED_DIR}")
    mcp.run(transport="sse")
