# LangSmith source contract

The LangSmith source supports two selectable authentication models. `api_key` sends the bound credential in `X-API-Key`; `bearer_token` sends the same bound credential as `Authorization: Bearer`. Selection comes from `auth_model`. The trusted host owns the credential value.

`X-Organization-Id` and `X-Tenant-Id` are request scope, not provider record identity. Families that use workspace scope bind both headers and persist both configured scope values as event attributes. Organization-only families bind `X-Organization-Id`.

The catalog contains 13 families. Current organization is a singleton. Projects, feedback, and datasets use bounded `offset` and `limit` query pagination. Runs use `POST /api/v1/runs/query`: filters, the page limit, selected fields, and the next cursor are JSON-body values; the response continuation is `$.cursors.next`. Audit logs use a query cursor and read the response continuation from `$.cursor`.

The compiled connector catalog is the runtime authority for all 13 families. The shared host applies the selected authentication and scope headers, keeps run continuations in the JSON body, keeps audit continuations in the query, and advances the durable checkpoint only after accepted events are committed. The provider-local Go loader is retired and must not be restored.
