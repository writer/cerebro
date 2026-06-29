# Avaza

Generated Source Runtime SDK scaffold for `avaza`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/avaza`
- Health endpoint: `/source-runtimes/health?source_id=avaza`
- Source health receipt: `sources/avaza/source_health_receipt.json`
- EvidenceCAS reference kind: `avaza.evidence_cas_reference`

## Families

- `projectmember`, emits `avaza.projectmember`, reads `/api/ProjectMember`
- `lookup`, emits `avaza.lookup`, reads `/api/ExpenseGroup/Lookup`
- `userprofile`, emits `avaza.userprofile`, reads `/api/UserProfile`
- `webhook`, emits `avaza.webhook`, reads `/api/Webhook`
- `bill`, emits `avaza.bill`, reads `/api/Bill`
- `billpayment`, emits `avaza.billpayment`, reads `/api/BillPayment`
- `company`, emits `avaza.company`, reads `/api/Company`
- `contact`, emits `avaza.contact`, reads `/api/Contact`
- `creditnote`, emits `avaza.creditnote`, reads `/api/CreditNote`
- `currency`, emits `avaza.currency`, reads `/api/Currency`
- `estimate`, emits `avaza.estimate`, reads `/api/Estimate`
- `expense`, emits `avaza.expense`, reads `/api/Expense`

## Tests

- `go test ./sources/avaza ./internal/sourceprojection -count=1`
- `make catalog-check`
