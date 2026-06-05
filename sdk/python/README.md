# Cerebro Python SDK Helpers

The Python helpers target the current Cerebro bootstrap API. They are maintained directly in this folder and are separate from the retired historical Agent SDK gateway.

## Install For Local Development

```bash
cd sdk/python
python3 -m pip install -e .
```

The package requires Python 3.10+ and currently depends on `protobuf`.

## Client Basics

```python
from cerebro_sdk import Client

client = Client(
    base_url="http://127.0.0.1:8080",
    api_key=None,  # Set when CEREBRO_API_AUTH_ENABLED=true.
)

integration = client.integration(
    runtime_id="local-sdk-demo",
    tenant_id="local",
    integration="demo",
)

integration.ensure_runtime()
claims = [
    integration.attr(
        integration.ref("service", "example-api", "Example API"),
        "owner",
        "platform",
        source_event_id="demo-claim-1",
    )
]
integration.write_claims(claims)
```

Useful environment variables for examples:

```bash
export CEREBRO_BASE_URL=http://127.0.0.1:8080
export CEREBRO_API_KEY=
export CEREBRO_TENANT_ID=local
export CEREBRO_RUNTIME_ID=local-jira-posture
```

Run the Jira posture example against a local Cerebro stack:

```bash
python3 examples/jira_posture_onboarding.py
```

## Checks

```bash
python3 -m unittest discover -s tests
# Or from the repository root:
make sdk-python-test
make sdk-dependency-audit
```

Use `make sdk-test` from the repository root when changes affect shared SDK behavior.
