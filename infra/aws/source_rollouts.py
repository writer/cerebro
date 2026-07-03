from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any


class SourceRuntimeRolloutError(ValueError):
    pass


@dataclass(frozen=True)
class SourceRuntimeRolloutExpansion:
    source_secret_keys: list[str] = field(default_factory=list)
    source_runtimes: list[dict[str, Any]] = field(default_factory=list)
    orchestrator_schedules: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _ScheduleCandidate:
    runtime_id: str
    config: dict[str, Any]
    schedule: dict[str, Any]
    group_size: int
    group_key: tuple[Any, ...]


def expand_source_runtime_rollouts(rollouts: Any) -> SourceRuntimeRolloutExpansion:
    if rollouts in (None, ""):
        return SourceRuntimeRolloutExpansion()
    if not isinstance(rollouts, list):
        raise SourceRuntimeRolloutError("sourceRuntimeRollouts must be a list")

    secret_keys: list[str] = []
    runtimes: list[dict[str, Any]] = []
    schedules: list[dict[str, Any]] = []
    runtime_index = 0

    for rollout_index, rollout in enumerate(rollouts):
        if not isinstance(rollout, dict):
            raise SourceRuntimeRolloutError(f"sourceRuntimeRollouts[{rollout_index}] must be an object")
        if rollout.get("enabled", True) is False:
            continue
        source_id = _required_string(rollout, "sourceId", f"sourceRuntimeRollouts[{rollout_index}]")
        runtime_prefix = _string(rollout.get("runtimePrefix")) or f"writer-{_slug(source_id)}"
        tenant_id = _string(rollout.get("tenantId")) or "writer"
        token_key = _string(rollout.get("tokenKey"))
        token_config_key = _string(rollout.get("tokenConfigKey")) or "token"
        per_page = rollout.get("perPage")
        common_config = _string_map(rollout.get("commonConfig") or {}, f"sourceRuntimeRollouts[{rollout_index}].commonConfig")
        schedule_config = rollout.get("schedule")
        if schedule_config is None:
            schedule_config = {}
        if not isinstance(schedule_config, dict):
            raise SourceRuntimeRolloutError(f"sourceRuntimeRollouts[{rollout_index}].schedule must be an object")
        schedule_enabled = schedule_config.get("enabled", True) is not False

        families = rollout.get("families") or []
        if not isinstance(families, list) or not families:
            raise SourceRuntimeRolloutError(f"sourceRuntimeRollouts[{rollout_index}].families must be a non-empty list")

        rollout_schedule_candidates: list[_ScheduleCandidate] = []
        for family_index, family in enumerate(families):
            family_path = f"sourceRuntimeRollouts[{rollout_index}].families[{family_index}]"
            family_name, local_id, family_config, family_token_key, family_token_config_key, family_schedule_config = _family_settings(
                family,
                family_path,
            )
            config = {"family": family_name, **common_config}
            if per_page is not None:
                config["per_page"] = str(per_page)
            config.update(family_config)
            effective_token_key = family_token_key or token_key
            if effective_token_key:
                config[family_token_config_key or token_config_key] = f"env:{effective_token_key}"

            runtime_id = f"{runtime_prefix}-{local_id}"
            runtimes.append({
                "id": runtime_id,
                "sourceId": source_id,
                "tenantId": tenant_id,
                "config": config,
            })
            _append_env_refs(secret_keys, config)
            for key in rollout.get("secretKeys") or []:
                _append_unique(secret_keys, _string(key))

            if schedule_enabled:
                rollout_schedule_candidates.append(_schedule_candidate(runtime_id, {**schedule_config, **family_schedule_config}, runtime_index))
            runtime_index += 1

        schedules.extend(_rollout_schedules(runtime_prefix, rollout_schedule_candidates))

    return SourceRuntimeRolloutExpansion(secret_keys, runtimes, schedules)


def apply_source_runtime_rollouts(config: dict[str, Any]) -> dict[str, Any]:
    expansion = expand_source_runtime_rollouts(config.get("sourceRuntimeRollouts") or [])
    if not expansion.source_secret_keys and not expansion.source_runtimes and not expansion.orchestrator_schedules:
        return dict(config)
    out = dict(config)
    source_secret_keys = list(out.get("sourceSecretKeys") or [])
    for secret_key in expansion.source_secret_keys:
        _append_unique(source_secret_keys, secret_key)
    out["sourceSecretKeys"] = source_secret_keys
    out["sourceRuntimes"] = list(out.get("sourceRuntimes") or []) + expansion.source_runtimes
    out["orchestratorSchedules"] = list(out.get("orchestratorSchedules") or []) + expansion.orchestrator_schedules
    return out


def _family_settings(family: Any, path: str) -> tuple[str, str, dict[str, str], str, str, dict[str, Any]]:
    if isinstance(family, str):
        family_name = family.strip()
        if not family_name:
            raise SourceRuntimeRolloutError(f"{path} must be non-empty")
        return family_name, _slug(family_name), {}, "", "", {}
    if not isinstance(family, dict):
        raise SourceRuntimeRolloutError(f"{path} must be a string or object")
    family_name = _required_string(family, "name", path)
    local_id = _string(family.get("localId")) or _slug(family_name)
    config = _string_map(family.get("config") or {}, f"{path}.config")
    schedule = family.get("schedule") or {}
    if not isinstance(schedule, dict):
        raise SourceRuntimeRolloutError(f"{path}.schedule must be an object")
    return family_name, local_id, config, _string(family.get("tokenKey")), _string(family.get("tokenConfigKey")), schedule


def _schedule(runtime_id: str, config: dict[str, Any], index: int) -> dict[str, Any]:
    expression = _string(config.get("expression"))
    if not expression:
        cadence_hours = _positive_int(config.get("cadenceHours"), "schedule.cadenceHours", 6)
        minute_step = _positive_int(config.get("minuteStep"), "schedule.minuteStep", 7)
        minute = (index * minute_step) % 60
        hour = index % cadence_hours
        expression = f"cron({minute} {hour}/{cadence_hours} * * ? *)"
    name = _string(config.get("name"))
    suffix = _string(config.get("nameSuffix")) or "inventory"
    if not name:
        name = f"{runtime_id.removeprefix('writer-')}-{suffix}"
    max_name_length = _positive_int(config.get("nameMaxLength"), "schedule.nameMaxLength", 0)
    if max_name_length and len(name) > max_name_length:
        name = _short_name(name, max_name_length)
    return {
        "name": name,
        "scheduleExpression": expression,
        "taskCount": _positive_int(config.get("taskCount"), "schedule.taskCount", 1),
        "backend": _schedule_backend(config.get("backend")),
        "flexibleWindowMinutes": _positive_int(config.get("flexibleWindowMinutes"), "schedule.flexibleWindowMinutes", 60),
        "state": _schedule_state(config.get("state") or config.get("scheduleState")),
        "command": _schedule_command(f"runtime_id={runtime_id}", config),
    }


def _schedule_candidate(runtime_id: str, config: dict[str, Any], index: int) -> _ScheduleCandidate:
    schedule = _schedule(runtime_id, config, index)
    return _ScheduleCandidate(
        runtime_id=runtime_id,
        config=config,
        schedule=schedule,
        group_size=_positive_int(config.get("groupSize"), "schedule.groupSize", 1),
        group_key=_schedule_group_key(config),
    )


def _rollout_schedules(runtime_prefix: str, candidates: list[_ScheduleCandidate]) -> list[dict[str, Any]]:
    schedules: list[dict[str, Any]] = []
    grouped: dict[tuple[Any, ...], list[_ScheduleCandidate]] = {}
    for candidate in candidates:
        if candidate.group_size <= 1:
            schedules.append(candidate.schedule)
            continue
        grouped.setdefault(candidate.group_key, []).append(candidate)

    group_number = 1
    for compatible_candidates in grouped.values():
        group_size = compatible_candidates[0].group_size
        for start in range(0, len(compatible_candidates), group_size):
            chunk = compatible_candidates[start:start + group_size]
            if len(chunk) == 1:
                schedules.append(chunk[0].schedule)
                continue
            schedules.append(_grouped_schedule(runtime_prefix, chunk, group_number))
            group_number += 1
    return schedules


def _schedule_group_key(config: dict[str, Any]) -> tuple[Any, ...]:
    expression = _string(config.get("expression"))
    cadence_key: tuple[str, str | int]
    if expression:
        cadence_key = ("expression", expression)
    else:
        cadence_key = ("cadenceHours", _positive_int(config.get("cadenceHours"), "schedule.cadenceHours", 6))
    return (
        _positive_int(config.get("groupSize"), "schedule.groupSize", 1),
        cadence_key,
        _positive_int(config.get("taskCount"), "schedule.taskCount", 1),
        _schedule_backend(config.get("backend")),
        _positive_int(config.get("flexibleWindowMinutes"), "schedule.flexibleWindowMinutes", 60),
        _schedule_state(config.get("state") or config.get("scheduleState")),
        _positive_int(config.get("pageLimit"), "schedule.pageLimit", 20),
        _positive_int(config.get("graphPageLimit"), "schedule.graphPageLimit", 100),
        _positive_int(config.get("eventLimit"), "schedule.eventLimit", 1000),
    )


def _grouped_schedule(runtime_prefix: str, candidates: list[_ScheduleCandidate], group_number: int) -> dict[str, Any]:
    config = candidates[0].config
    runtime_ids = [candidate.runtime_id for candidate in candidates]
    suffix = _string(config.get("groupNameSuffix")) or _string(config.get("nameSuffix")) or "inventory"
    name_base = _string(config.get("groupName")) or f"{runtime_prefix.removeprefix('writer-')}-{suffix}"
    name = f"{name_base}-group-{group_number:02d}"
    max_name_length = _positive_int(config.get("nameMaxLength"), "schedule.nameMaxLength", 0)
    if max_name_length and len(name) > max_name_length:
        name = _short_name(name, max_name_length)
    return {
        "name": name,
        "scheduleExpression": candidates[0].schedule["scheduleExpression"],
        "taskCount": _positive_int(config.get("taskCount"), "schedule.taskCount", 1),
        "backend": _schedule_backend(config.get("backend")),
        "flexibleWindowMinutes": _positive_int(config.get("flexibleWindowMinutes"), "schedule.flexibleWindowMinutes", 60),
        "state": _schedule_state(config.get("state") or config.get("scheduleState")),
        "command": _schedule_command(f"runtime_ids={','.join(runtime_ids)}", config),
    }


def _schedule_command(runtime_filter: str, config: dict[str, Any]) -> list[str]:
    return [
        "orchestrator",
        "run",
        runtime_filter,
        f"page_limit={_positive_int(config.get('pageLimit'), 'schedule.pageLimit', 20)}",
        f"graph_page_limit={_positive_int(config.get('graphPageLimit'), 'schedule.graphPageLimit', 100)}",
        f"event_limit={_positive_int(config.get('eventLimit'), 'schedule.eventLimit', 1000)}",
    ]


def _schedule_backend(value: Any) -> str:
    backend = _string(value) or "scheduler"
    if backend not in {"eventbridge", "scheduler"}:
        raise SourceRuntimeRolloutError("schedule.backend must be eventbridge or scheduler")
    return backend


def _schedule_state(value: Any) -> str:
    state = (_string(value) or "ENABLED").upper()
    if state not in {"ENABLED", "DISABLED"}:
        raise SourceRuntimeRolloutError("schedule.state must be ENABLED or DISABLED")
    return state


def _required_string(values: dict[str, Any], key: str, path: str) -> str:
    value = _string(values.get(key))
    if not value:
        raise SourceRuntimeRolloutError(f"{path}.{key} is required")
    return value


def _string(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _string_map(values: Any, path: str) -> dict[str, str]:
    if not isinstance(values, dict):
        raise SourceRuntimeRolloutError(f"{path} must be an object")
    out: dict[str, str] = {}
    for key, value in values.items():
        text_key = _string(key)
        if not text_key:
            raise SourceRuntimeRolloutError(f"{path} keys must be non-empty")
        out[text_key] = _string(value)
    return out


def _positive_int(value: Any, path: str, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise SourceRuntimeRolloutError(f"{path} must be a positive integer") from exc
    if parsed < 1:
        raise SourceRuntimeRolloutError(f"{path} must be a positive integer")
    return parsed


def _short_name(value: str, max_length: int) -> str:
    if max_length < 8:
        raise SourceRuntimeRolloutError("schedule.nameMaxLength must be at least 8")
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:6]
    return f"{value[: max_length - 7].rstrip('-')}-{digest}"


def _slug(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def _append_env_refs(out: list[str], config: dict[str, str]) -> None:
    for value in config.values():
        text = _string(value)
        if text.startswith("env:"):
            _append_unique(out, text.removeprefix("env:").strip())


def _append_unique(out: list[str], value: str) -> None:
    if value and value not in out:
        out.append(value)
