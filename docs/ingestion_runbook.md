# Ingestion Connector Runbook

This runbook explains the shared utilities introduced for provider ingestion
and how to extend normalization rules when onboarding a new connector.

## Connector Helper Utilities

- Import helpers from `cerebro.providers.utils` instead of re‑implementing
  pagination or retry loops.
- Preferred APIs:
  - `call_sync_with_retries` for blocking SDK calls.
  - `call_async_with_retries` for async clients.
  - `iterate_sync_iterator` for paginated iterators returned by provider SDKs.
- All helpers apply exponential backoff (default 0.5s, 3 attempts) and accept a
  provider logger.
- Example usage:
  ```python
  from cerebro.providers.utils import call_sync_with_retries

  items = await call_sync_with_retries(
      lambda: client.list_items().get("Items", []),
      exceptions=(ClientError,),
      logger=logger,
  )
  ```

## Severity & Exposure Normalization

- Standard mappings live in `cerebro.collectors.normalization`.
- Call `normalize_severity(value, provider=<name>)` before storing or returning
  alert severity.
- `normalize_exposure` provides similar handling for exposure labels.
- Update `_NORMALIZATION_CONFIG` with provider-specific overrides and extend
  unit tests in `tests_unit/collectors/test_normalization.py` when adding new
  mappings.

## Testing Checklist

- Run connector utility tests: `PYTHONPATH=src pytest tests_unit/providers/test_connector_utils.py`.
- Run normalization tests: `PYTHONPATH=src pytest tests_unit/collectors/test_normalization.py`.
- Execute targeted provider suites or integration tests when modifying
  provider implementations.
