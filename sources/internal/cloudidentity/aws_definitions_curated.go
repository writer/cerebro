package cloudidentitysource

import (
	"fmt"
	"strings"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// awsCuratedOperationProfile is a hand-verified, conservative upper bound of
// one operation's dependent permissions, read directly from that operation's
// own AWS API reference "Permissions" section — the only place AWS documents
// resource/configuration-triggered dependencies (for example SSE-KMS or
// directory-bucket session authorization) that the live Service Reference
// JSON omits entirely (verified against serviceDefinitions). A profile
// only ADDS to whatever the live feed already
// resolved for the same (service, operation); it never removes or overrides
// a live-fed permission. Only operations explicitly reviewed this way appear
// here; every other operation stays DependenciesComplete=false.
type awsCuratedOperationProfile struct {
	// addPermissions are permissions always required beyond the live feed.
	addPermissions []string
	// addConditionalPermissions are permissions required only in specific,
	// documented scenarios (SSE-KMS, directory buckets, optional request
	// headers, ...).
	addConditionalPermissions []string
	// primaryPermissions are this operation's hand-verified baseline
	// unconditional permission(s), read from the same API reference page as
	// addPermissions/addConditionalPermissions. The curated row's
	// exhaustiveness claim (DependenciesComplete=true) is only honest when
	// every one of these actually appears in the merged Permissions set --
	// whether because the live Service Reference feed supplied it or
	// because addPermissions did. A live feed that fails to publish them
	// (e.g. empty AuthorizedActions) must never silently inherit
	// DependenciesComplete=true from an otherwise-matching curated row.
	primaryPermissions []string
	// sourceURL is the exact AWS API reference page this profile was
	// verified against.
	sourceURL string
}

// awsCuratedOperationProfiles are keyed by "service:Operation" exactly as
// published by the live feed (operation name, not SDK method name).
//
// Verified 2026 against the live pages cited below:
//   - GetObject/PutObject: SSE-KMS requires kms:GenerateDataKey and
//     kms:Decrypt ("If the object is encrypted with/using SSE-KMS, you must
//     also have the kms:GenerateDataKey and kms:Decrypt permissions");
//     directory buckets require s3express:CreateSession session auth for
//     both operations.
//   - DeleteObject: no KMS dependency (deleting does not decrypt); directory
//     buckets require s3express:CreateSession. The live feed's three actions
//     (BypassGovernanceRetention/DeleteObject/DeleteObjectVersion) already
//     match the doc's "Permissions" section exactly.
//   - ListBuckets: the doc confirms s3:ListAllMyBuckets alone is sufficient
//     ("To grant IAM permission to use this operation, you must add the
//     s3:ListAllMyBuckets policy action") and explicitly states the
//     operation "is not supported for directory buckets", so there is no
//     s3express or KMS dependency to add; the live feed's single action is
//     already the complete, verified set.
var awsCuratedOperationProfiles = map[string]awsCuratedOperationProfile{
	"s3:GetObject": {
		addConditionalPermissions: []string{"kms:GenerateDataKey", "kms:Decrypt", "s3express:CreateSession"},
		primaryPermissions:        []string{"s3:GetObject"},
		sourceURL:                 "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html",
	},
	"s3:PutObject": {
		addConditionalPermissions: []string{"kms:GenerateDataKey", "kms:Decrypt", "s3express:CreateSession"},
		primaryPermissions:        []string{"s3:PutObject"},
		sourceURL:                 "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html",
	},
	"s3:DeleteObject": {
		addConditionalPermissions: []string{"s3express:CreateSession"},
		primaryPermissions:        []string{"s3:BypassGovernanceRetention", "s3:DeleteObject", "s3:DeleteObjectVersion"},
		sourceURL:                 "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html",
	},
	"s3:ListBuckets": {
		primaryPermissions: []string{"s3:ListAllMyBuckets"},
		sourceURL:          "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html",
	},
}

// awsApplyCuratedOperationProfile supplements def with any hand-verified
// additions for its exact (Service, Operation) pair. DependenciesComplete
// is set true only when a curated profile exists AND every one of its
// primaryPermissions is present in the merged Permissions set (confirmed by
// the live feed, since curated rows only ever ADD conditional/dependency
// permissions, never the operation's own base action). A curated row whose
// primary permission(s) the live feed failed to supply (e.g. empty
// AuthorizedActions, a partial set) returns DependenciesComplete=false plus
// a scoped gap: the curated additions alone are never an exhaustive claim.
// Every other operation is returned unchanged with DependenciesComplete
// left false.
func awsApplyCuratedOperationProfile(def ci.OperationDefinition, now time.Time) (ci.OperationDefinition, []ci.Gap) {
	opScope := def.Service + ":" + def.Operation
	profile, ok := awsCuratedOperationProfiles[opScope]
	if !ok {
		return def, nil
	}
	def.Permissions = awsAppendDeduped(def.Permissions, profile.addPermissions)
	def.ConditionalPermissions = awsAppendDeduped(def.ConditionalPermissions, profile.addConditionalPermissions)

	var gaps []ci.Gap
	if missing := awsMissingPermissions(def.Permissions, profile.primaryPermissions); len(missing) > 0 {
		def.DependenciesComplete = false
		gaps = append(gaps, awsGap("aws_curated_primary_permissions_missing", opScope, "Curated profile for this operation requires confirmed primary permission(s) ("+strings.Join(missing, ", ")+") that the live Service Reference feed did not supply; the curated conditional/dependent additions alone are not an exhaustive permission set"))
	} else {
		def.DependenciesComplete = true
	}
	digest := ci.Digest(fmt.Sprintf("%s|%s", strings.Join(profile.addPermissions, ","), strings.Join(profile.addConditionalPermissions, ",")))
	def.References = append(def.References, awsReference(profile.sourceURL, opScope, now, digest))
	return def, gaps
}

// awsMissingPermissions returns the entries of want not present in have,
// preserving want's order.
func awsMissingPermissions(have []string, want []string) []string {
	if len(want) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(have))
	for _, permission := range have {
		seen[permission] = true
	}
	var missing []string
	for _, permission := range want {
		if !seen[permission] {
			missing = append(missing, permission)
		}
	}
	return missing
}

func awsAppendDeduped(existing []string, additions []string) []string {
	if len(additions) == 0 {
		return existing
	}
	seen := make(map[string]bool, len(existing))
	for _, value := range existing {
		seen[value] = true
	}
	for _, value := range additions {
		if !seen[value] {
			existing = append(existing, value)
			seen[value] = true
		}
	}
	return existing
}
