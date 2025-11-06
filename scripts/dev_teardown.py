#!/usr/bin/env python3
"""Gracefully stop processes launched by scripts/dev_stack.py."""

from __future__ import annotations

import json
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List


STATE_DIR = Path.home() / ".cerebro" / "dev_stack"
STATE_PATH = STATE_DIR / "active.json"


@dataclass
class ManagedProcess:
    name: str
    pid: int


def is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def load_managed_processes() -> List[ManagedProcess]:
    if not STATE_PATH.exists():
        print("No active dev stack state file found; nothing to stop.")
        return []

    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        print(f"Unable to read state file ({exc}); removing stale entry.")
        STATE_PATH.unlink(missing_ok=True)
        return []

    processes: List[ManagedProcess] = []
    for entry in data.get("processes", []):
        pid = entry.get("pid")
        name = entry.get("name", "unknown")
        if isinstance(pid, int) and is_process_alive(pid):
            processes.append(ManagedProcess(name=name, pid=pid))

    if not processes:
        STATE_PATH.unlink(missing_ok=True)
        print("No managed processes are still running; cleared stale state file.")

    return processes


def terminate_process(proc: ManagedProcess, timeout: float = 10.0) -> None:
    print(f"Stopping {proc.name} (pid={proc.pid})...")
    try:
        os.kill(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        print(f"  {proc.name} already exited.")
        return
    except PermissionError:
        print(f"  Permission denied when signaling {proc.name}; skipping.")
        return

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_process_alive(proc.pid):
            print(f"  {proc.name} stopped cleanly.")
            return
        time.sleep(0.5)

    print(f"  {proc.name} did not stop within {timeout}s; sending SIGKILL.")
    try:
        os.kill(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        print(f"  {proc.name} exited while escalating signal.")
        return
    except PermissionError:
        print(f"  Permission denied when killing {proc.name}; manual intervention required.")
        return

    if not is_process_alive(proc.pid):
        print(f"  {proc.name} forcefully stopped.")
    else:
        print(f"  {proc.name} is still running; manual cleanup needed.")


def main() -> int:
    processes = load_managed_processes()
    if not processes:
        return 0

    for proc in processes:
        terminate_process(proc)

    STATE_PATH.unlink(missing_ok=True)
    print("Cleared dev stack state file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
