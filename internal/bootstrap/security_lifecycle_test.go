package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/sourcehttp/organizationalgraph"
)

type securityLifecycleErrorService struct {
	cerebrov1connect.UnimplementedSecurityLifecycleServiceHandler
}

func (securityLifecycleErrorService) ListSecurityLifecycle(
	_ context.Context,
	request *connect.Request[cerebrov1.ListSecurityLifecycleRequest],
) (*connect.Response[cerebrov1.ListSecurityLifecycleResponse], error) {
	query := request.Msg.GetQuery()
	if query.GetPageToken() == "unavailable" {
		return nil, connect.NewError(
			connect.CodeUnavailable,
			errors.New("graph read is unavailable"),
		)
	}
	if query.GetPageToken() != "" || len(query.GetOwnerUrns()) > 0 {
		return nil, connect.NewError(
			connect.CodeInvalidArgument,
			errors.New("lifecycle selector is invalid"),
		)
	}
	return nil, connect.NewError(connect.CodeInternal, errors.New("backend read failed"))
}

func TestSecurityLifecycleHandlerPreservesClientAndBackendErrors(t *testing.T) {
	_, upstreamHandler := cerebrov1connect.NewSecurityLifecycleServiceHandler(
		securityLifecycleErrorService{},
	)
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	store, err := organizationalgraph.NewQueryStore(
		nil,
		upstream.URL,
		strings.Repeat("a", 32),
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewQueryStore() error = %v", err)
	}
	app := &App{deps: Dependencies{SecurityLifecycleQueries: store}}
	for _, test := range []struct {
		name   string
		query  string
		status int
	}{
		{
			name:   "invalid page token",
			query:  "?page_token=invalid",
			status: http.StatusBadRequest,
		},
		{
			name:   "cross tenant owner selector",
			query:  "?owner_urn=urn%3Acerebro%3Atenant-b%3Ateam%3Asecurity",
			status: http.StatusBadRequest,
		},
		{
			name:   "invalid findings only",
			query:  "?findings_only=ture",
			status: http.StatusBadRequest,
		},
		{
			name:   "incomplete subject locator",
			query:  "?subject_kind=credential&authority_id=authority-a",
			status: http.StatusBadRequest,
		},
		{
			name:   "ambiguous subject locator kind",
			query:  "?subject_kind=credential&subject_kind=certificate&authority_id=authority-a&stable_locator=slot-a",
			status: http.StatusBadRequest,
		},
		{
			name:   "graph unavailable",
			query:  "?page_token=unavailable",
			status: http.StatusServiceUnavailable,
		},
		{
			name:   "backend failure",
			status: http.StatusBadGateway,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodGet,
				"/v1/security/lifecycle"+test.query,
				nil,
			)
			request = request.WithContext(context.WithValue(
				request.Context(),
				authContextKey{},
				authContext{principal: authPrincipal{TenantID: "tenant-a"}},
			))
			response := httptest.NewRecorder()

			app.handleListSecurityLifecycle(response, request)

			if response.Code != test.status {
				t.Fatalf(
					"handleListSecurityLifecycle() status = %d, want %d (body %q)",
					response.Code,
					test.status,
					response.Body.String(),
				)
			}
		})
	}
}
