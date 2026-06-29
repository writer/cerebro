# DrChrono

Generated Source Runtime SDK scaffold for `drchrono`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/drchrono`
- Health endpoint: `/source-runtimes/health?source_id=drchrono`
- Source health receipt: `sources/drchrono/source_health_receipt.json`
- EvidenceCAS reference kind: `drchrono.evidence_cas_reference`

## Families

- `patient_risk_assessment`, emits `drchrono.patient_risk_assessment`, reads `/api/patient_risk_assessments`
- `comm_log`, emits `drchrono.comm_log`, reads `/api/comm_logs`
- `care_team_member`, emits `drchrono.care_team_member`, reads `/api/care_team_members`
- `user`, emits `drchrono.user`, reads `/api/users`
- `implantable_device`, emits `drchrono.implantable_device`, reads `/api/implantable_devices`
- `patient_payment_log`, emits `drchrono.patient_payment_log`, reads `/api/patient_payment_log`
- `user_group`, emits `drchrono.user_group`, reads `/api/user_groups`
- `allergy`, emits `drchrono.allergy`, reads `/api/allergies`
- `amendment`, emits `drchrono.amendment`, reads `/api/amendments`
- `appointment`, emits `drchrono.appointment`, reads `/api/appointments`
- `appointment_profile`, emits `drchrono.appointment_profile`, reads `/api/appointment_profiles`
- `appointment_template`, emits `drchrono.appointment_template`, reads `/api/appointment_templates`

## Tests

- `go test ./sources/drchrono ./internal/sourceprojection -count=1`
- `make catalog-check`
