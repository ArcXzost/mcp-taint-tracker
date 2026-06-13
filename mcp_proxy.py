import sys
import json
import uuid
import time
import threading
import argparse
import subprocess
import requests

API_URL = "http://localhost:8000/api/sessions"

def main():
    parser = argparse.ArgumentParser(description="MCP Reverse Proxy / Interception Layer")
    parser.add_argument("--target", required=True, help="The underlying MCP server command (e.g., 'npx -y mcp-server-sqlite')")
    parser.add_argument("--session-id", default=None, help="Optional session ID for the dashboard")
    args = parser.parse_args()

    session_id = args.session_id or str(uuid.uuid4())
    print(f"[mcp_proxy] Starting interception for session: {session_id}", file=sys.stderr)

    # Initialize the session in the dashboard
    try:
        requests.post(f"{API_URL}/{session_id}/events", json=[], timeout=2) # Just to ensure session exists, though backend handles creation
    except Exception as e:
        print(f"[mcp_proxy] Warning: Could not connect to Tracker API: {e}", file=sys.stderr)

    # Dictionary to track pending tool calls: { message_id: { "tool_name": "...", "input": {...} } }
    pending_calls = {}
    pending_lock = threading.Lock()

    # Start the target process
    import shlex
    target_args = shlex.split(args.target)
    
    try:
        proc = subprocess.Popen(
            target_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr, # Pass stderr through to the actual console
            bufsize=0 # Unbuffered
        )
    except Exception as e:
        print(f"[mcp_proxy] Failed to start target process: {e}", file=sys.stderr)
        sys.exit(1)

    # Thread 1: Client -> Server (Intercept tool calls)
    def client_to_server():
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                break
            
            # Forward immediately
            proc.stdin.write(line)
            proc.stdin.flush()

            # Intercept
            try:
                msg = json.loads(line.decode('utf-8'))
                if msg.get("method") == "tools/call":
                    msg_id = msg.get("id")
                    params = msg.get("params", {})
                    tool_name = params.get("name")
                    arguments = params.get("arguments", {})
                    
                    if msg_id is not None:
                        with pending_lock:
                            pending_calls[msg_id] = {
                                "tool_name": tool_name,
                                "input": arguments
                            }
                        # print(f"[mcp_proxy] Intercepted tool call: {tool_name}", file=sys.stderr)
            except Exception:
                pass # Not JSON or parse error

    # Thread 2: Server -> Client (Intercept tool results)
    def server_to_client():
        while True:
            line = proc.stdout.readline()
            if not line:
                break

            # Forward immediately
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

            # Intercept
            try:
                msg = json.loads(line.decode('utf-8'))
                msg_id = msg.get("id")
                
                if msg_id is not None:
                    with pending_lock:
                        if msg_id in pending_calls:
                            call_data = pending_calls.pop(msg_id)
                            result = msg.get("result", {})
                            
                            # Construct the Tracker Event
                            event = {
                                "tool_name": call_data["tool_name"],
                                "input": call_data["input"],
                                "output": result,
                                "timestamp": time.time()
                            }
                            
                            # print(f"[mcp_proxy] Intercepted result for: {call_data['tool_name']}", file=sys.stderr)
                            
                            # Async POST to dashboard
                            def post_event(e):
                                try:
                                    requests.post(f"{API_URL}/{session_id}/events", json=e, timeout=2)
                                except:
                                    pass
                            
                            threading.Thread(target=post_event, args=(event,), daemon=True).start()
                            
            except Exception:
                pass

    t1 = threading.Thread(target=client_to_server, daemon=True)
    t2 = threading.Thread(target=server_to_client, daemon=True)
    t1.start()
    t2.start()

    proc.wait()
    sys.exit(proc.returncode)

if __name__ == "__main__":
    main()