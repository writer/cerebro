package okta

import (
	"context"
	"embed"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/oktaasset"
)

//go:embed catalog.yaml
var catalogFS embed.FS

type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	mfaFactorBackoffs    []time.Duration
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:          spec,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	return s.families.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	auditList := s.listAudit
	return sourcecdk.NewFamilyEngineWithSourceID("okta", s.parseSettings, func(settings settings) string {
		return settings.family
	},
		oktaFamily(oktaFamilyOptions[auditRecord]{
			Name:  familyAudit,
			Label: "okta audit log",
			List:  auditList,
			Event: auditEvent,
			Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
				if err := oktaCheck(ctx, settings, auditList, "okta audit log"); err != nil {
					return nil, err
				}
				urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:org:%s", settings.domain, settings.domain))
				if err != nil {
					return nil, err
				}
				return []sourcecdk.URN{urn}, nil
			},
			CursorFallback: func(entry auditRecord) string { return entry.UUID },
		}),
		oktaFamily(oktaFamilyOptions[adminRoleRecord]{
			Name:  familyAdminRole,
			Label: "okta admin roles",
			List:  s.listAdminRoles,
			Event: adminRoleEvent,
			URN: func(settings settings, role adminRoleRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:admin_role:%s:%s", settings.domain, settings.userID, firstNonEmpty(role.ID, role.Type, role.Label)), nil
			},
		}),
		oktaFamily(oktaFamilyOptions[appAssignmentRecord]{
			Name:  familyAppAssign,
			Label: "okta app assignments",
			List:  s.listAppAssignments,
			Event: appAssignmentEvent,
			URN: func(settings settings, assignment appAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:app_assignment:%s:%s", settings.domain, settings.appID, firstNonEmpty(assignment.ID, assignmentEmail(assignment))), nil
			},
		}),
		oktaFamily(oktaFamilyOptions[appRecord]{
			Name:  familyApplication,
			Label: "okta applications",
			List:  s.listApplications,
			Event: applicationEvent,
			URN: func(settings settings, app appRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:application:%s", settings.domain, app.ID), nil
			},
		}),
		s.assetFamily("api_token", "okta API tokens", "/api/v1/api-tokens", "api_token", oktaasset.KindAPIToken, false),
		s.assetFamily("authorization_server", "okta authorization servers", "/api/v1/authorizationServers", "authorization_server", oktaasset.KindAuthorizationServer, true),
		s.assetFamily("brand", "okta brands", "/api/v1/brands", "brand", oktaasset.KindBrand, true),
		s.assetFamily("device_assurance", "okta device assurance policies", "/api/v1/device-assurances", "device_assurance", oktaasset.KindDeviceAssurance, false),
		s.assetFamily("event_hook", "okta event hooks", "/api/v1/eventHooks", "event_hook", oktaasset.KindEventHook, false),
		s.assetFamily("inline_hook", "okta inline hooks", "/api/v1/inlineHooks", "inline_hook", oktaasset.KindInlineHook, false),
		s.assetFamily("log_stream", "okta log streams", "/api/v1/logStreams", "log_stream", oktaasset.KindLogStream, true),
		s.policyRuleFamily(),
		s.assetFamily(familyAuthenticator, "okta authenticators", "/api/v1/authenticators", "authenticator", oktaasset.KindAuthenticator, false),
		s.threatInsightFamily(),
		oktaFamily(oktaFamilyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "okta groups",
			List:  s.listGroups,
			Event: groupEvent,
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:group:%s", settings.domain, group.ID), nil
			},
		}),
		s.assetFamily(familyIDP, "okta identity providers", "/api/v1/idps", "identity_provider", oktaasset.KindIdentityProvider, true),
		s.assetFamily(familyNetworkZone, "okta network zones", "/api/v1/zones", "network_zone", oktaasset.KindNetworkZone, true),
		oktaFamily(oktaFamilyOptions[userRecord]{
			Name:  familyGroupMember,
			Label: "okta group memberships",
			List:  s.listGroupMembers,
			Event: groupMembershipEvent,
			URN: func(settings settings, member userRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:group_membership:%s:%s", settings.domain, settings.groupID, member.ID), nil
			},
		}),
		s.assetFamily(familyTrustedOrigin, "okta trusted origins", "/api/v1/trustedOrigins", "trusted_origin", oktaasset.KindTrustedOrigin, true),
		oktaFamily(oktaFamilyOptions[userRecord]{
			Name:         familyUser,
			Label:        "okta users",
			List:         s.listUsers,
			Enrich:       s.enrichUsersWithMFAFactors,
			Probe:        s.probeLatestUser,
			ProbeOptions: oktaUserFreshnessReadOptions(),
			Event:        userEvent,
			URN: func(settings settings, user userRecord) (string, error) {
				urn, err := userURN(settings.domain, user.ID)
				if err != nil {
					return "", err
				}
				return urn.String(), nil
			},
			CursorFallback: func(user userRecord) string { return user.ID },
		}),
	)
}

func (s *Source) assetFamily(name string, label string, path string, urnFamily string, kind string, queryParams bool) sourcecdk.Family[settings] {
	return oktaasset.Family(oktaasset.FamilyOptions[settings]{
		Name: name, Label: label, Path: path, URNFamily: urnFamily, Kind: kind, QueryParams: queryParams,
		Settings: oktaAssetSettings,
		List:     s.listAssetRecords,
	})
}

func (s *Source) listAssetRecords(ctx context.Context, settings settings, requestPath string, query url.Values, label string) ([]oktaasset.Record, string, error) {
	return listJSONRecords[oktaasset.Record](ctx, s, settings, requestPath, query, label, nil)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
