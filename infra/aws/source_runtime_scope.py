from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from aws.source_rollouts import apply_source_runtime_rollouts


def load_cerebro_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    config = loaded.get("config")
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a top-level config mapping")
    scoped = {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }
    return apply_source_runtime_rollouts(scoped)


def runtime_id_from_command(command: Any) -> str:
    if not isinstance(command, list):
        return ""
    for arg in command:
        text = str(arg).strip()
        if text.startswith("runtime_id="):
            return text.split("=", 1)[1].strip()
    return ""


def runtime_value(runtime: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = runtime.get(key)
        if value is not None:
            return str(value).strip()
    return ""


def runtime_source_id(runtime: dict[str, Any]) -> str:
    return runtime_value(runtime, "sourceId", "source_id")


def runtime_family(runtime: dict[str, Any]) -> str:
    config = runtime.get("config") or {}
    if not isinstance(config, dict):
        return ""
    return str(config.get("family") or "").strip()


def declared_runtime_ids(
    config: dict[str, Any],
    source_id: str = "",
    requested: set[str] | None = None,
    families: set[str] | None = None,
) -> list[str]:
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return []
    requested = requested or set()
    families = families or set()
    runtime_ids = []
    for runtime in runtimes:
        if not isinstance(runtime, dict):
            continue
        runtime_id = str(runtime.get("id", "")).strip()
        if not runtime_id:
            continue
        if source_id and runtime_source_id(runtime) != source_id:
            continue
        if requested and runtime_id not in requested:
            continue
        if families and runtime_family(runtime) not in families:
            continue
        runtime_ids.append(runtime_id)
    return sorted(runtime_ids)


def declared_aws_families(config: dict[str, Any]) -> set[str]:
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return set()
    return {
        runtime_family(runtime)
        for runtime in runtimes
        if isinstance(runtime, dict)
        and runtime_source_id(runtime) == "aws"
        and runtime_family(runtime)
    }


def observability_runtime_ids(
    config: dict[str, Any],
    source_id: str,
    requested: set[str] | None = None,
    families: set[str] | None = None,
    *,
    enabled: bool = True,
) -> list[str]:
    entries = config.get("sourceRuntimeObservability") or []
    if not isinstance(entries, list):
        return []
    requested = requested or set()
    families = families or set()
    runtime_ids: list[str] = []
    seen_enabled: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        runtime_id = str(entry.get("sourceRuntimeId") or entry.get("source_runtime_id") or "").strip()
        source_system = str(entry.get("sourceSystem") or entry.get("source_system") or "").strip()
        runtime_class = str(entry.get("runtimeClass") or entry.get("runtime_class") or "").strip()
        if not runtime_id or source_system != source_id:
            continue
        if requested and runtime_id not in requested:
            continue
        if families and runtime_class not in families:
            continue
        is_enabled = bool(entry.get("enabled", False))
        if is_enabled:
            if runtime_id in seen_enabled:
                raise ValueError(f"duplicate enabled sourceRuntimeObservability entry for {runtime_id!r}")
            seen_enabled.add(runtime_id)
        if is_enabled is enabled:
            runtime_ids.append(runtime_id)
    return sorted(set(runtime_ids))


def env_ref(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text.startswith("env:"):
        return ""
    return text.removeprefix("env:").strip()


def env_refs(value: Any, path: str = "") -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    ref = env_ref(value)
    if ref or (isinstance(value, str) and value.strip().startswith("env:")):
        refs.append((ref, path))
    elif isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            refs.extend(env_refs(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            refs.extend(env_refs(child, f"{path}[{index}]"))
    return refs


def source_runtime_env_refs(source_runtimes: list[Any]) -> list[str]:
    refs: set[str] = set()
    for runtime in source_runtimes:
        if not isinstance(runtime, dict):
            continue
        runtime_config = runtime.get("config") or {}
        if not isinstance(runtime_config, dict):
            continue
        refs.update(env_name for env_name, _path in env_refs(runtime_config) if env_name)
    return sorted(refs)


def source_secret_key_env_name(secret_key: Any) -> str:
    if isinstance(secret_key, dict):
        return str(secret_key.get("name") or "").strip()
    return str(secret_key or "").strip()


def config_for_runtime_scope(config: dict[str, Any], runtime_ids: set[str]) -> dict[str, Any]:
    if not runtime_ids:
        return dict(config)
    scoped = dict(config)
    source_runtimes = [
        runtime
        for runtime in (config.get("sourceRuntimes") or [])
        if isinstance(runtime, dict) and str(runtime.get("id") or "").strip() in runtime_ids
    ]
    scoped["sourceRuntimes"] = source_runtimes
    env_names = set(source_runtime_env_refs(source_runtimes))
    scoped["sourceSecretKeys"] = [
        secret_key
        for secret_key in (config.get("sourceSecretKeys") or [])
        if source_secret_key_env_name(secret_key) in env_names
    ]
    return scoped


def s3_prefix_covers(configured_prefix: str, runtime_prefix: str) -> bool:
    configured = str(configured_prefix).strip()
    runtime = str(runtime_prefix).strip()
    if not configured:
        return False
    return runtime == configured or runtime.startswith(configured)
