#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from provision_otel_collector_config import bool_value, load_stack, render_collector_config, service_name, stack_name


READY_MARKER = "Everything is ready. Begin running and processing data."
DEFAULT_DOCKER_PULL_RETRIES = 3
TRANSIENT_REGISTRY_ERRORS = (
    "toomanyrequests",
    "too many requests",
    "rate exceeded",
    "429",
)


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True)


def docker_logs(docker_bin: str, container_name: str) -> str:
    completed = run_command([docker_bin, "logs", container_name])
    return (completed.stdout or "") + (completed.stderr or "")


def remove_container(docker_bin: str, container_name: str) -> None:
    run_command([docker_bin, "rm", "-f", container_name])


def image_pull_rate_limited(detail: str) -> bool:
    normalized = detail.lower()
    return any(marker in normalized for marker in TRANSIENT_REGISTRY_ERRORS)


def pull_image_with_retries(*, docker_bin: str, image: str, attempts: int = DEFAULT_DOCKER_PULL_RETRIES) -> None:
    latest_detail = ""
    for attempt in range(1, attempts + 1):
        completed = run_command([docker_bin, "pull", image])
        if completed.returncode == 0:
            return
        latest_detail = (completed.stderr or completed.stdout or "").strip()
        if not image_pull_rate_limited(latest_detail) or attempt == attempts:
            break
        time.sleep(min(2**attempt, 10))
    raise RuntimeError(f"failed to pull collector image {image}: {latest_detail}")


def container_running(docker_bin: str, container_name: str) -> bool:
    completed = run_command([docker_bin, "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", container_name])
    return completed.returncode == 0 and completed.stdout.strip().startswith("true ")


def start_collector(
    *,
    docker_bin: str,
    image: str,
    container_name: str,
    config: str,
    region: str,
) -> str:
    command = [
        docker_bin,
        "run",
        "-d",
        "--name",
        container_name,
        "-e",
        f"AOT_CONFIG_CONTENT={config}",
        "-e",
        f"AWS_REGION={region}",
        "-e",
        f"AWS_DEFAULT_REGION={region}",
        "-e",
        "AWS_EC2_METADATA_DISABLED=true",
        image,
    ]
    completed = run_command(command)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        if image_pull_rate_limited(detail):
            pull_image_with_retries(docker_bin=docker_bin, image=image)
            completed = run_command(command)
            if completed.returncode == 0:
                return completed.stdout.strip()
            detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"failed to start collector image {image}: {detail}")
    return completed.stdout.strip()


def transient_registry_error(exc: BaseException) -> bool:
    detail = str(exc).lower()
    return any(marker in detail for marker in TRANSIENT_REGISTRY_ERRORS)


def wait_for_ready(*, docker_bin: str, container_name: str, timeout_seconds: int) -> str:
    deadline = time.monotonic() + timeout_seconds
    latest_logs = ""
    while time.monotonic() < deadline:
        latest_logs = docker_logs(docker_bin, container_name)
        if READY_MARKER in latest_logs:
            return latest_logs
        if not container_running(docker_bin, container_name):
            raise RuntimeError(f"collector exited before readiness:\n{latest_logs.strip()}")
        time.sleep(1)
    raise TimeoutError(f"collector did not become ready within {timeout_seconds}s:\n{latest_logs.strip()}")


def validate_stack_file(
    path: Path,
    *,
    docker_bin: str,
    region: str,
    timeout_seconds: int,
    allow_registry_unavailable: bool = False,
) -> str:
    stack = stack_name(path)
    config = load_stack(path)
    if not bool_value(config.get("otelCollectorEnabled")):
        return f"skipped: {path} otelCollectorEnabled is not true"
    image = str(config.get("otelCollectorImage") or "").strip()
    if not image:
        raise ValueError(f"{path}: otelCollectorImage is required when otelCollectorEnabled is true")
    rendered = render_collector_config(service_name(config, stack))
    container_name = f"cerebro-adot-validate-{uuid4().hex[:12]}"
    try:
        try:
            start_collector(
                docker_bin=docker_bin,
                image=image,
                container_name=container_name,
                config=rendered,
                region=region,
            )
        except RuntimeError as exc:
            if allow_registry_unavailable and transient_registry_error(exc):
                return f"registry-unavailable: {path} image={image}: {exc}"
            raise
        wait_for_ready(docker_bin=docker_bin, container_name=container_name, timeout_seconds=timeout_seconds)
    finally:
        remove_container(docker_bin, container_name)
    return f"validated: {path} image={image}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate rendered ADOT collector configs by booting the configured collector image.")
    parser.add_argument("--stack-file", type=Path, action="append", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--docker-bin", default="docker")
    parser.add_argument(
        "--allow-registry-unavailable",
        action="store_true",
        help="Treat transient registry pull rate limits as a skipped runtime check for static CI.",
    )
    args = parser.parse_args(argv)

    for stack_file in args.stack_file:
        print(
            validate_stack_file(
                stack_file,
                docker_bin=args.docker_bin,
                region=args.region,
                timeout_seconds=args.timeout_seconds,
                allow_registry_unavailable=args.allow_registry_unavailable,
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", flush=True)
        raise SystemExit(1)
