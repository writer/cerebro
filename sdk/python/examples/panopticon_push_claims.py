import os
from pprint import pprint
from typing import Optional

from cerebro_sdk import onboard_panopticon_push_claims


def main() -> None:
    runtime_id = optional_string(os.environ.get("CEREBRO_RUNTIME_ID")) or "writer-panopticon-push"
    claims = [
        {
            "subject_ref": {
                "urn": f"urn:cerebro:writer:runtime:{runtime_id}:alert:alert-123",
                "entity_type": "alert",
                "label": "Alert 123",
            },
            "subject_urn": f"urn:cerebro:writer:runtime:{runtime_id}:alert:alert-123",
            "predicate": "exists",
            "claim_type": "existence",
            "status": "asserted",
            "source_event_id": "panopticon-alert-123",
            "observed_at": "2026-06-08T12:00:00Z",
            "valid_from": "2026-06-08T12:00:00Z",
            "attributes": {"family": "alert", "severity": "high"},
        },
        {
            "subject_ref": {
                "urn": f"urn:cerebro:writer:runtime:{runtime_id}:alert:alert-123",
                "entity_type": "alert",
                "label": "Alert 123",
            },
            "subject_urn": f"urn:cerebro:writer:runtime:{runtime_id}:alert:alert-123",
            "predicate": "severity",
            "object_value": "high",
            "claim_type": "attribute",
            "status": "asserted",
            "source_event_id": "panopticon-alert-123",
            "observed_at": "2026-06-08T12:00:00Z",
            "valid_from": "2026-06-08T12:00:00Z",
            "attributes": {"family": "alert"},
        },
    ]
    result = onboard_panopticon_push_claims(
        base_url=optional_string(os.environ.get("CEREBRO_BASE_URL")) or "http://127.0.0.1:8080",
        api_key=optional_string(os.environ.get("CEREBRO_API_KEY")),
        tenant_id=optional_string(os.environ.get("CEREBRO_TENANT_ID")) or "writer",
        runtime_id=runtime_id,
        claims=claims,
    )
    pprint(result)


def optional_string(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


if __name__ == "__main__":
    main()
