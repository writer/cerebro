import pathlib
import sys

import importlib.util
import pytest

# Dynamically load the monitoring module without executing project-wide imports.
INFRA_ROOT = pathlib.Path(__file__).resolve().parents[2]
monitoring_path = INFRA_ROOT / "infra" / "aws" / "monitoring.py"

spec = importlib.util.spec_from_file_location("aws.monitoring", monitoring_path)
monitoring = importlib.util.module_from_spec(spec)
sys.modules["aws.monitoring"] = monitoring
assert spec.loader is not None
spec.loader.exec_module(monitoring)

_build_ecs_alarm_resource_name = monitoring._build_ecs_alarm_resource_name


def test_build_ecs_alarm_resource_name_includes_index_suffix() -> None:
    assert _build_ecs_alarm_resource_name("cerebro-prod", 2) == "cerebro-prod-ecs-2"


def test_build_ecs_alarm_resource_name_rejects_negative_index() -> None:
    with pytest.raises(ValueError):
        _build_ecs_alarm_resource_name("cerebro-prod", -1)
