#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
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


ROOT_DIR = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Cerebro development services")
    parser.add_argument("--api-port", type=int, default=8000, help="Port for the API server")
    parser.add_argument("--skip-worker", action="store_true", help="Skip starting the Celery worker")
    parser.add_argument("--skip-beat", action="store_true", help="Skip starting the Celery beat scheduler")
    parser.add_argument("--frontend", action="store_true", help="Launch the frontend dev server")
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
            )
        )

    if not args.skip_beat:
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

    if args.frontend:
        specs.append(build_frontend_spec())

    return specs


def build_frontend_spec() -> ProcSpec:
    import shutil

    frontend_dir = ROOT_DIR / "frontend"
    command: Sequence[str]

    if shutil.which("bun") and (frontend_dir / "bun.lock").exists():
        command = ["bun", "dev"]
    elif shutil.which("npm"):
        command = ["npm", "run", "dev"]
    elif shutil.which("yarn"):
        command = ["yarn", "dev"]
    else:
        raise RuntimeError("No Node package manager (bun, npm, yarn) available for frontend dev server")

    node_modules = frontend_dir / "node_modules"
    if not node_modules.exists():
        raise RuntimeError(
            f"frontend dependencies missing. Install them in {frontend_dir} before launching the dev server"
        )

    env = os.environ.copy()
    env.setdefault("PORT", "3000")

    return ProcSpec(name="frontend", command=command, cwd=frontend_dir, env=env,)


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
    specs = build_specs(args)
    if not specs:
        print("No services selected")
        return 0

    processes: List[asyncio.subprocess.Process] = []
    names: List[str] = []
    output_tasks: List[asyncio.Task[None]] = []

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
