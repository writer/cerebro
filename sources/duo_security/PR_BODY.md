## Summary

- Deepens the `duo_security` source runtime against Duo Admin API v1/v2/v3.
- Uses Duo signed Admin API authentication.
- Adds administrators, phones, hardware tokens, WebAuthn credentials, bypass codes, endpoints, and authentication logs.
- Wires new emitted kinds into graph projection for identity review, MFA factor posture, device posture, sensitive bypass-code records, and audit context.

## Runtime Contract

- Source type: `json_api`
- Auth model: `duo_hmac` for Admin API v1/v2; `duo_hmac_v5` for integrations
- Health path: `/admin/v1/users`
- Log windows: `mintime` and `maxtime` for activity and authentication logs

## Tests

- `go test ./sources/duo_security ./internal/sourceprojection -count=1`
- `go run ./tools/catalogcheck`
