package graph

import (
	"context"
	"time"
)

const defaultMonitorDebounce = 500 * time.Millisecond

func monitorDebounceWindow(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultMonitorDebounce
	}
	if interval < defaultMonitorDebounce {
		return interval
	}
	return defaultMonitorDebounce
}

func monitorMaxStaleness(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultMonitorDebounce
	}
	return interval
}

func runReactiveMonitorLoop(
	ctx context.Context,
	g *Graph,
	stopCh <-chan struct{},
	interval time.Duration,
	filter GraphChangeFilter,
	scan func(),
) error {
	debounce := monitorDebounceWindow(interval)
	maxStaleness := monitorMaxStaleness(interval)

	scan()

	sub := g.SubscribeChanges(filter, 1)
	defer sub.Close()

	var (
		debounceTimer   *time.Timer
		debounceTimerC  <-chan time.Time
		stalenessTimer  *time.Timer
		stalenessTimerC <-chan time.Time
		dirty           bool
	)

	resetDebounceTimer := func() {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(debounce)
		} else {
			if !debounceTimer.Stop() {
				select {
				case <-debounceTimer.C:
				default:
				}
			}
			debounceTimer.Reset(debounce)
		}
		debounceTimerC = debounceTimer.C
	}

	stopDebounceTimer := func() {
		if debounceTimer == nil {
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceTimerC = nil
	}
	defer stopDebounceTimer()

	startStalenessTimer := func() {
		if stalenessTimer == nil {
			stalenessTimer = time.NewTimer(maxStaleness)
		} else {
			if !stalenessTimer.Stop() {
				select {
				case <-stalenessTimer.C:
				default:
				}
			}
			stalenessTimer.Reset(maxStaleness)
		}
		stalenessTimerC = stalenessTimer.C
	}

	stopStalenessTimer := func() {
		if stalenessTimer == nil {
			return
		}
		if !stalenessTimer.Stop() {
			select {
			case <-stalenessTimer.C:
			default:
			}
		}
		stalenessTimerC = nil
	}
	defer stopStalenessTimer()

	scanAndClearDirty := func() {
		stopDebounceTimer()
		stopStalenessTimer()
		dirty = false
		scan()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stopCh:
			return nil
		case _, ok := <-sub.Changes():
			if !ok {
				return nil
			}
			if !dirty {
				dirty = true
				startStalenessTimer()
			}
			resetDebounceTimer()
		case <-debounceTimerC:
			scanAndClearDirty()
		case <-stalenessTimerC:
			scanAndClearDirty()
		}
	}
}

func toxicCombinationMonitorChangeFilter() GraphChangeFilter {
	return GraphChangeFilter{
		NodeKinds: []NodeKind{
			NodeKindUser,
			NodeKindPerson,
			NodeKindIdentityAlias,
			NodeKindRole,
			NodeKindGroup,
			NodeKindServiceAccount,
			NodeKindInternet,
			NodeKindService,
			NodeKindWorkload,
			NodeKindBucket,
			NodeKindBucketPolicyStatement,
			NodeKindBucketPublicAccessBlock,
			NodeKindBucketEncryptionConfig,
			NodeKindBucketLoggingConfig,
			NodeKindBucketVersioningConfig,
			NodeKindInstance,
			NodeKindDatabase,
			NodeKindSecret,
			NodeKindFunction,
			NodeKindWorkloadScan,
			NodeKindPackage,
			NodeKindVulnerability,
			NodeKindPod,
			NodeKindDeployment,
			NodeKindNamespace,
			NodeKindClusterRole,
			NodeKindClusterRoleBinding,
			NodeKindRoleBinding,
			NodeKindConfigMap,
			NodeKindPersistentVolume,
			NodeKindApplication,
			NodeKindCustomer,
			NodeKindCompany,
			NodeKindDeal,
			NodeKindOpportunity,
			NodeKindSubscription,
			NodeKindInvoice,
		},
		EdgeKinds: []EdgeKind{
			EdgeKindCanAssume,
			EdgeKindMemberOf,
			EdgeKindResolvesTo,
			EdgeKindAliasOf,
			EdgeKindReportsTo,
			EdgeKindCanRead,
			EdgeKindCanWrite,
			EdgeKindCanDelete,
			EdgeKindCanAdmin,
			EdgeKindConnectsTo,
			EdgeKindCalls,
			EdgeKindRuns,
			EdgeKindDependsOn,
			EdgeKindConfigures,
			EdgeKindExposedTo,
			EdgeKindDeployedFrom,
			EdgeKindOriginatedFrom,
			EdgeKindProvisionedAs,
			EdgeKindOwns,
			EdgeKindSubscribedTo,
			EdgeKindBilledBy,
			EdgeKindWorksAt,
			EdgeKindManagedBy,
			EdgeKindAssignedTo,
			EdgeKindRenews,
			EdgeKindEscalatedTo,
			EdgeKindInteractedWith,
			EdgeKindLocatedIn,
			EdgeKindTargets,
			EdgeKindBasedOn,
			EdgeKindTriggeredBy,
			EdgeKindCausedBy,
			EdgeKindHasScan,
			EdgeKindFoundVuln,
			EdgeKindContainsPkg,
			EdgeKindContains,
			EdgeKindAffectedBy,
			EdgeKindHasCredentialFor,
		},
	}
}

func attackPathMonitorChangeFilter() GraphChangeFilter {
	return GraphChangeFilter{}
}

func privilegeEscalationMonitorChangeFilter() GraphChangeFilter {
	return GraphChangeFilter{
		NodeKinds: []NodeKind{
			NodeKindUser,
			NodeKindPerson,
			NodeKindIdentityAlias,
			NodeKindRole,
			NodeKindGroup,
			NodeKindServiceAccount,
			NodeKindPermissionBoundary,
		},
		EdgeKinds: []EdgeKind{
			EdgeKindCanAssume,
			EdgeKindMemberOf,
			EdgeKindResolvesTo,
			EdgeKindAliasOf,
			EdgeKindCanRead,
			EdgeKindCanWrite,
			EdgeKindCanDelete,
			EdgeKindCanAdmin,
		},
	}
}
