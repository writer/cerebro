# Security Regression Harness

This harness keeps recent Droid findings from becoming one-off fixes. Add new scanner findings here only after they are backed by a repeatable check.

| Finding class | Regression check |
| --- | --- |
| Cypher comment/string validator bypass, unsafe procedures, and oversized branch limits | `go test ./internal/graphagent` plus `FuzzValidatorMaliciousCorpus` seeds in `internal/graphagent/validator_test.go`. |
| Ask ontology drift, scoped deterministic templates, and brittle `attributes_json` extraction | `go test ./internal/graphagent`; deterministic source/top-risk templates return bounded candidate rows and parse JSON metadata in Go before emitting rows. |
| Connector SSRF, DNS rebinding, redirects, and unbounded response reads | `go test ./internal/sourcehttp ./sources/... ./tools/archtests`; `TestSourcesUseSharedHTTPSafety` rejects raw source `http.Client` construction and direct response-body reads, while `TestProductionBodyReadsAreBounded` rejects unbounded production `io.ReadAll` calls. |
| Oversized VulnDB advisory feeds | `go test ./internal/vulndb`; feed importers return `ErrVulnDBFeedTooLarge` before decoding over-limit OSV, CISA KEV, EPSS, or NVD payloads. |
| Spoofable `X-Forwarded-For`, DPoP `htu`, and audit client IP drift | `go test ./internal/bootstrap ./internal/config`; request origin is resolved through `internal/bootstrap/request_origin.go` and configured by `CEREBRO_PUBLIC_ORIGIN`, `CEREBRO_TRUSTED_PROXY_CIDRS`, and `CEREBRO_TRUSTED_PROXY_COUNT`. |
| Candidate promote/reject lost updates and partial lifecycle attempts | `go test ./internal/findings`; lifecycle decisions use stable IDs and recover completed concurrent CAS transitions. |
| OAuth identity email used as authority before verification | `go test ./internal/mcpoauth ./internal/bootstrap -run 'TestEntitlementForIdentityRequiresVerifiedEmailClaim|TestAuthorizationCodeSubjectRequiresVerifiedEmail|TestMCPOAuthOIDCClientVerifiesIDToken'` plus `make check-structural`; `mcpoauth.Identity` carries only typed `VerifiedEmail` values and `noidentityemail` rejects direct identity email field reads. |

Before dismissing a future scanner report as a false positive, add one of:

- A unit or fuzz seed proving the reported payload is blocked.
- An archtest preventing the unsafe API pattern from being reintroduced.
- A deployment/config assertion when the finding depends on runtime environment.

Run the focused harness locally with:

```bash
go test ./internal/graphagent ./internal/sourcehttp ./internal/bootstrap ./internal/config ./internal/findings ./internal/vulndb ./internal/mcpoauth ./tools/archtests
make check-structural
```
