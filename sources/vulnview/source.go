package vulnview

import (
	"context"
	"embed"
	"net"
	"net/http"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID = "vulnview"

	familySite    = "site"
	familyScan    = "scan"
	familyAsset   = "asset"
	familyFinding = "finding"
)

// Source reads VulnView attack-surface, asset, and standardized-finding data.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
	tokenCache           *sourcecdk.OAuthTokenCache
}

// New constructs the VulnView source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:          spec,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
		tokenCache:    sourcecdk.NewOAuthTokenCache(tokenExpirationLeeway),
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

// Spec returns static VulnView source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured VulnView family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns canonical VulnView URNs for one configured page.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages VulnView records and emits vulnview.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

// ReadWithCheckpoint gives checkpoint-aware families (the standardized finding
// export) the durable checkpoint; sourcecdk calls it instead of Read.
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	return s.families.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string {
		return settings.family
	},
		s.family(familySite, "/sites"),
		s.family(familyScan, "/scans"),
		s.family(familyAsset, "/assets"),
		s.findingFamily(),
	)
}

func (s *Source) family(name string, path string) sourcecdk.Family[settings] {
	return familyFromLister(name, func(ctx context.Context, settings settings, cursor string, pageSize int) ([]record, string, error) {
		return s.list(ctx, settings, path, cursor, pageSize)
	})
}

// familyFromLister builds a Family whose Check/Discover/Read page through
// list, mapping records to events via the generic eventFromRecord.
func familyFromLister(name string, list func(context.Context, settings, string, int) ([]record, string, error)) sourcecdk.Family[settings] {
	return familyFromListerWithEvent(name, list, func(settings settings, rec record) *primitives.Event {
		return eventFromRecord(settings, name, rec)
	})
}

// familyFromListerWithEvent is familyFromLister for a family whose event
// shaping needs more than the generic family-name kind/schema.
func familyFromListerWithEvent(name string, list func(context.Context, settings, string, int) ([]record, string, error), event func(settings, record) *primitives.Event) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: name,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := list(ctx, settings, "", 1)
			return wrapFamilyErr(name, err)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := list(ctx, settings, "", settings.perPage)
			if err != nil {
				return nil, wrapFamilyErr(name, err)
			}
			return urnsFor(settings, name, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := list(ctx, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, wrapFamilyErr(name, err)
			}
			return sourcecdk.PullFromRecords(records, next,
				func(rec record) (*primitives.Event, error) { return event(settings, rec), nil },
				func(rec record) string { return strings.TrimSpace(rec.ID) },
			)
		},
	}
}

func wrapFamilyErr(name string, err error) error { return sourcecdk.WrapFamilyErr(sourceID, name, err) }

func (s *Source) list(ctx context.Context, settings settings, path string, cursor string, pageSize int) ([]record, string, error) {
	var response listResponse
	query := settings.query()
	query.Set("limit", strconv.Itoa(pageSize))
	sourcecdk.AddQueryParam(query, "cursor", cursor)
	if err := s.getJSON(ctx, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	records := make([]record, 0, len(response.Items))
	for _, item := range response.Items {
		rec, err := recordFromRaw(settings.family, item)
		if err != nil {
			return nil, "", err
		}
		if rec.ID == "" {
			continue
		}
		records = append(records, rec)
	}
	if serverPaged(cursor, pageSize, len(records), response.NextCursor) {
		return records, strings.TrimSpace(response.NextCursor), nil
	}
	return sourcecdk.PageByOffset(records, cursor, pageSize)
}

// serverPaged reports whether the provider's own cursor/offset pagination
// should be trusted for this page instead of falling back to local
// offset-based paging: either the provider returned an explicit next
// cursor, or a resumed page came back at or under the page size (a
// provider-exhausted page).
func serverPaged(cursor string, pageSize int, recordCount int, nextCursor string) bool {
	return strings.TrimSpace(nextCursor) != "" || (strings.TrimSpace(cursor) != "" && recordCount <= pageSize)
}
