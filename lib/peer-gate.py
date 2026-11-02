#!/usr/bin/python3
"""Peer-validation gate for the DSH sudo broker.

This build of Node does not expose SO_PEERCRED, so Python checks the Unix
socket peer UID and process ancestry, then relays one request/response line
over the gate's stdin/stdout to the host plugin.  No additional local socket
is exposed to the sandbox.
"""
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import uuid

PUBLIC, AUDIT = sys.argv[1:3]
DSH_RE = re.compile(r"\b(dsh|dsh-desktop|deepseek-harness)\b")
responses = {}
responses_lock = threading.Lock()


def read_proc(pid, name):
    try:
        with open(f"/proc/{pid}/{name}", "rb") as handle:
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""


def is_sudo_client(pid):
    command = read_proc(pid, "cmdline").replace("\0", " ")
    return "sudo-client.py" in command


def has_dsh_ancestor(pid):
    current = pid
    for _ in range(5):
        if current <= 1:
            return False
        command = read_proc(current, "cmdline").replace("\0", " ")
        if DSH_RE.search(command):
            return True
        status = read_proc(current, "status")
        match = re.search(r"^PPid:\s*(\d+)", status, re.MULTILINE)
        if not match:
            return False
        current = int(match.group(1))
    return False


def audit_refused(pid):
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "session": "unknown",
        "cwd": "",
        "command": "",
        "kind": "command",
        "level": None,
        "categories": [],
        "score": None,
        "confirm": "refused",
        "exitCode": -1,
        "durationMs": 0,
        "clientPid": pid,
        "reason": "refused:peer",
    }
    try:
        os.makedirs(os.path.dirname(AUDIT), exist_ok=True)
        fd = os.open(AUDIT, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(record, ensure_ascii=False) + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass


def read_request(connection):
    data = b""
    while b"\n" not in data:
        chunk = connection.recv(65536)
        if not chunk:
            return None
        data += chunk
        if len(data) > 65536:
            return None
    return data.split(b"\n", 1)[0].decode("utf-8", "replace")


def handle(connection):
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, _gid = struct.unpack("3i", raw)
    except OSError:
        connection.close()
        return

    if uid != os.getuid() or not is_sudo_client(pid) or not has_dsh_ancestor(pid):
        audit_refused(pid)
        connection.close()
        return

    try:
        line = read_request(connection)
        if line is None:
            connection.close()
            return

        request_id = uuid.uuid4().hex
        response_queue = queue.Queue(maxsize=1)
        with responses_lock:
            responses[request_id] = response_queue
        try:
            message = json.dumps({"id": request_id, "line": line}, ensure_ascii=False)
            sys.stdout.buffer.write(message.encode("utf-8") + b"\n")
            sys.stdout.buffer.flush()
            response = response_queue.get(timeout=180)
            if response:
                connection.sendall(response.encode("utf-8"))
        finally:
            with responses_lock:
                responses.pop(request_id, None)
    except (OSError, queue.Empty):
        pass
    finally:
        try:
            connection.close()
        except OSError:
            pass


def read_responses():
    for raw in sys.stdin.buffer:
        try:
            message = json.loads(raw.decode("utf-8"))
            request_id = message.get("id")
            with responses_lock:
                response_queue = responses.get(request_id)
            if response_queue is not None:
                response_queue.put(message.get("data", ""))
        except Exception:
            continue


def main():
    threading.Thread(target=read_responses, daemon=True).start()
    try:
        os.unlink(PUBLIC)
    except OSError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(PUBLIC)
    os.chmod(PUBLIC, 0o600)
    server.listen(8)
    while True:
        connection, _ = server.accept()
        threading.Thread(target=handle, args=(connection,), daemon=True).start()


if __name__ == "__main__":
    main()
