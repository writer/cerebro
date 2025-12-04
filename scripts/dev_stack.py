#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence


@dataclass
class ProcSpec:
    name: str
    command: Sequence[str]
    cwd: Optional[Path] = None
    env: Optional[Dict[str, str]] = None


STATE_DIR = Path.home() / ".cerebro" / "dev_stack"
STATE_PATH = STATE_DIR / "active.json"


def is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    else:
        return True


def ensure_no_active_stack() -> None:
    if not STATE_PATH.exists():
        return

    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        STATE_PATH.unlink(missing_ok=True)
        return

    active_entries = []
    for proc in data.get("processes", []):
        pid = proc.get("pid")
        if isinstance(pid, int) and is_process_alive(pid):
            active_entries.append(proc)

    if active_entries:
        process_list = ", ".join(f"{entry.get('name','unknown')} (pid={entry['pid']})" for entry in active_entries)
        raise RuntimeError(
            "An existing dev stack appears to be running: "
            f"{process_list}. Run 'make dev-stop' before starting a new stack."
        )

    STATE_PATH.unlink(missing_ok=True)


def write_state(processes: Sequence[asyncio.subprocess.Process], names: Sequence[str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "processes": [
            {
                "name": name,
                "pid": process.pid,
            }
            for process, name in zip(processes, names)
        ]
    }
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def clear_state() -> None:
    STATE_PATH.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Cerebro development services")
    parser.add_argument("--api-port", type=int, default=8000, help="Port for the API server")
    parser.add_argument("--skip-worker", action="store_true", help="Skip starting the Celery worker")
    parser.add_argument("--skip-beat", action="store_true", help="Skip starting the Celery beat scheduler")
    parser.add_argument("--flower", action="store_true", help="Launch Flower for Celery monitoring")
    return parser.parse_args()


def build_specs(args: argparse.Namespace) -> List[ProcSpec]:
    specs: List[ProcSpec] = [
        ProcSpec(
            name="api",
            command=[
                sys.executable,
                "-m",
                "uvicorn",
                "cerebro.api.main:app",
                "--reload",
                "--host",
                "0.0.0.0",
                "--port",
                str(args.api_port),
            ],
        )
    ]

    if not args.skip_worker:
        worker_env = os.environ.copy()
        worker_env.setdefault("CELERY_PROCESS_ROLE", "worker")
        specs.append(
            ProcSpec(
                name="worker",
                command=[
                    sys.executable,
                    "-m",
                    "celery",
                    "-A",
                    "cerebro.tasks.celery_app",
                    "worker",
                    "-l",
                    "info",
                ],
                env=worker_env,
            )
        )

    if not args.skip_beat:
        beat_env = os.environ.copy()
        beat_env.setdefault("CELERY_PROCESS_ROLE", "beat")
        specs.append(
            ProcSpec(
                name="beat",
                command=[
                    sys.executable,
                    "-m",
                    "celery",
                    "-A",
                    "cerebro.tasks.celery_app",
                    "beat",
                    "-l",
                    "info",
                ],
                env=beat_env,
            )
        )

    if args.flower:
        specs.append(
            ProcSpec(
                name="flower",
                command=[
                    sys.executable,
                    "-m",
                    "celery",
                    "-A",
                    "cerebro.tasks.celery_app",
                    "flower",
                    "--port",
                    "5555",
                ],
            )
        )

    return specs


async def create_process(spec: ProcSpec) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *spec.command,
        cwd=str(spec.cwd) if spec.cwd else None,
        env=spec.env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def pipe_stream(stream: asyncio.StreamReader, prefix: str) -> None:
    try:
        while True:
            line = await stream.readline()
            if not line:
                break
            print(f"[{prefix}] {line.decode(errors='ignore').rstrip()}")
    except asyncio.CancelledError:
        pass


async def terminate_process(process: asyncio.subprocess.Process, name: str, timeout: float = 10.0) -> None:
    if process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        print(f"[{name}] did not terminate in {timeout}s, killing")
        process.kill()
        await process.wait()


async def run_stack(args: argparse.Namespace) -> int:
    ensure_no_active_stack()
    specs = build_specs(args)
    if not specs:
        print("No services selected")
        return 0

    processes: List[asyncio.subprocess.Process] = []
    names: List[str] = []
    output_tasks: List[asyncio.Task[None]] = []
    state_written = False

    for spec in specs:
        try:
            process = await create_process(spec)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Failed to start {spec.name}: {exc}") from exc
        processes.append(process)
        names.append(spec.name)
        if process.stdout:
            output_tasks.append(asyncio.create_task(pipe_stream(process.stdout, spec.name)))
        if process.stderr:
            output_tasks.append(asyncio.create_task(pipe_stream(process.stderr, f"{spec.name}:err")))
        print(f"[{spec.name}] started (pid={process.pid})")

    try:
        write_state(processes, names)
        state_written = True

        stop_event = asyncio.Event()

        loop = asyncio.get_running_loop()

        def request_shutdown() -> None:
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, request_shutdown)
            except NotImplementedError:
                pass

        wait_tasks = {asyncio.create_task(proc.wait()): name for proc, name in zip(processes, names)}
        stop_task = asyncio.create_task(stop_event.wait())

        try:
            while True:
                done, _ = await asyncio.wait(
                    list(wait_tasks.keys()) + [stop_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if stop_task in done:
                    print("Shutdown requested")
                    break

                finished = done.intersection(wait_tasks.keys())
                if finished:
                    for task in finished:
                        name = wait_tasks[task]
                        returncode = task.result()
                        if returncode == 0:
                            print(f"[{name}] exited cleanly")
                        else:
                            print(f"[{name}] exited with code {returncode}")
                            stop_event.set()
                    break
        finally:
            stop_task.cancel()

        for task in wait_tasks.keys():
            task.cancel()

        for task in output_tasks:
            task.cancel()

        await asyncio.gather(*output_tasks, return_exceptions=True)

        await asyncio.gather(
            *(terminate_process(proc, name) for proc, name in zip(processes, names)),
            return_exceptions=True,
        )
    finally:
        if state_written:
            clear_state()

    return 0


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run_stack(args))
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
