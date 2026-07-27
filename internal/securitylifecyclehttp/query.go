// Package securitylifecyclehttp maps public HTTP selectors into the generated
// lifecycle query contract. Lifecycle identity and policy authority stay in
// Rust.
package securitylifecyclehttp

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var states = map[string]cerebrov1.SecurityLifecycleState{
	"active":   cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_ACTIVE,
	"expiring": cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_EXPIRING,
	"expired":  cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_EXPIRED,
	"rotated":  cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_ROTATED,
	"revoked":  cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_REVOKED,
	"inactive": cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_INACTIVE,
	"unknown":  cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_UNKNOWN,
}

func State(value string) (cerebrov1.SecurityLifecycleState, bool) {
	state, ok := states[value]
	return state, ok
}

func SetSubjectLocator(
	query *cerebrov1.SecurityLifecycleQuery,
	authorityID string,
	stableLocator string,
) error {
	if (authorityID == "") != (stableLocator == "") {
		return errors.New("authority_id and stable_locator must be provided together")
	}
	if authorityID == "" {
		return nil
	}
	if len(query.GetSubjectKinds()) != 1 {
		return errors.New("subject_kind must select one kind for a subject locator")
	}
	query.SubjectLocator = &cerebrov1.SecurityLifecycleSubjectLocator{
		SubjectKind:   query.GetSubjectKinds()[0],
		AuthorityId:   authorityID,
		StableLocator: stableLocator,
	}
	return nil
}
