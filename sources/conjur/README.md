# Conjur source contract

The Conjur source uses Basic authentication outside the credential-free source kernel. Operators may bind a username and password/API key pair, which becomes a base64-encoded `Authorization: Basic` value, or bind a precomputed Basic credential token. Credential values must remain in the trusted host.

The source reads four operations:

- `GET /resources`
- `GET /authenticators`
- `GET /resources/{account}`
- `GET /resources/{account}/{kind}`

Connection verification uses `GET /resources`. Resource operations use bounded `offset` and `limit` pagination. Responses that return resource metadata under `data.key_info` are converted from an object map into records in sorted key order. Each map key is the stable provider resource ID, and the nested value is available as `resource` for attribute mapping. The authenticator response reads `configured` as a list and does not send page-size parameters.

The compiled connector catalog is the runtime authority for all four families. The shared host applies either Basic credential form, bounds responses, normalizes the sorted resource-map records, and advances the durable checkpoint only after accepted events are committed. The provider-local Go loader is retired and must not be restored.
