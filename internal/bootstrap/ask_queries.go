package bootstrap

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	askQueryMaxNameBytes     = 200
	askQueryMaxQuestionBytes = 4000
)

var errAskQueriesUnavailable = errors.New("ask queries are not configured")

var askQueryErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(ports.ErrAskQueryNotFound), httpStatus: http.StatusNotFound},
	{match: matchesAnyError(errAskQueriesUnavailable), httpStatus: http.StatusServiceUnavailable},
	{match: matchesAnyError(errInvalidHTTPRequest), httpStatus: http.StatusBadRequest},
}

func writeAskQueryError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, askQueryErrorMappings)
}

type askQueryView struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Question  string `json:"question"`
	ScopeURN  string `json:"scope_urn,omitempty"`
	Model     string `json:"model,omitempty"`
	Pinned    bool   `json:"pinned"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type askQueryResponse struct {
	Query askQueryView `json:"query"`
}

type askQueryListResponse struct {
	Queries []askQueryView `json:"queries"`
}

type createAskQueryRequest struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Question string `json:"question"`
	ScopeURN string `json:"scope_urn"`
	Model    string `json:"model"`
	Pinned   *bool  `json:"pinned"`
}

type updateAskQueryRequest struct {
	Name     *string `json:"name"`
	Question *string `json:"question"`
	ScopeURN *string `json:"scope_urn"`
	Model    *string `json:"model"`
	Pinned   *bool   `json:"pinned"`
}

func (a *App) handleCreateAskQuery(w http.ResponseWriter, r *http.Request) {
	store := askQueryStore(a.deps.StateStore)
	if store == nil {
		writeAskQueryError(w, errAskQueriesUnavailable)
		return
	}
	var request createAskQueryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		writeAskQueryError(w, fmt.Errorf("%w: decode ask query: %w", errInvalidHTTPRequest, err))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	if tenantID == "" {
		writeAskQueryError(w, fmt.Errorf("%w: tenant_id is required", errInvalidHTTPRequest))
		return
	}
	name, question, err := normalizeAskQueryContent(request.Name, request.Question)
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	pinned := false
	if request.Pinned != nil {
		pinned = *request.Pinned
	}
	query := &ports.AskQuery{
		ID:       newAskQueryID(),
		TenantID: tenantID,
		Name:     name,
		Question: question,
		ScopeURN: strings.TrimSpace(request.ScopeURN),
		Model:    strings.TrimSpace(request.Model),
		Pinned:   pinned,
	}
	if err := store.PutAskQuery(r.Context(), query); err != nil {
		writeAskQueryError(w, err)
		return
	}
	stored, err := store.GetAskQuery(r.Context(), query.ID)
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, askQueryResponse{Query: newAskQueryView(stored)})
}

func (a *App) handleListAskQueries(w http.ResponseWriter, r *http.Request) {
	store := askQueryStore(a.deps.StateStore)
	if store == nil {
		writeAskQueryError(w, errAskQueriesUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeAskQueryError(w, fmt.Errorf("%w: %w", errInvalidHTTPRequest, err))
		return
	}
	queries, err := store.ListAskQueries(r.Context(), ports.AskQueryFilter{TenantID: tenantID, Limit: limit})
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	views := make([]askQueryView, 0, len(queries))
	for _, query := range queries {
		views = append(views, newAskQueryView(query))
	}
	writeJSON(w, http.StatusOK, askQueryListResponse{Queries: views})
}

func (a *App) handleUpdateAskQuery(w http.ResponseWriter, r *http.Request) {
	store := askQueryStore(a.deps.StateStore)
	if store == nil {
		writeAskQueryError(w, errAskQueriesUnavailable)
		return
	}
	existing, err := store.GetAskQuery(r.Context(), r.PathValue("queryID"))
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), existing.TenantID); err != nil {
		writeAskQueryError(w, normalizeIDLookupError(err, ports.ErrAskQueryNotFound))
		return
	}
	var request updateAskQueryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		writeAskQueryError(w, fmt.Errorf("%w: decode ask query: %w", errInvalidHTTPRequest, err))
		return
	}
	name := existing.Name
	if request.Name != nil {
		name = *request.Name
	}
	question := existing.Question
	if request.Question != nil {
		question = *request.Question
	}
	normalizedName, normalizedQuestion, err := normalizeAskQueryContent(name, question)
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	existing.Name = normalizedName
	existing.Question = normalizedQuestion
	if request.ScopeURN != nil {
		existing.ScopeURN = strings.TrimSpace(*request.ScopeURN)
	}
	if request.Model != nil {
		existing.Model = strings.TrimSpace(*request.Model)
	}
	if request.Pinned != nil {
		existing.Pinned = *request.Pinned
	}
	if err := store.PutAskQuery(r.Context(), existing); err != nil {
		writeAskQueryError(w, err)
		return
	}
	stored, err := store.GetAskQuery(r.Context(), existing.ID)
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, askQueryResponse{Query: newAskQueryView(stored)})
}

func (a *App) handleDeleteAskQuery(w http.ResponseWriter, r *http.Request) {
	store := askQueryStore(a.deps.StateStore)
	if store == nil {
		writeAskQueryError(w, errAskQueriesUnavailable)
		return
	}
	existing, err := store.GetAskQuery(r.Context(), r.PathValue("queryID"))
	if err != nil {
		writeAskQueryError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), existing.TenantID); err != nil {
		writeAskQueryError(w, normalizeIDLookupError(err, ports.ErrAskQueryNotFound))
		return
	}
	if err := store.DeleteAskQuery(r.Context(), existing.ID); err != nil {
		writeAskQueryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func normalizeAskQueryContent(name string, question string) (string, string, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return "", "", fmt.Errorf("%w: name is required", errInvalidHTTPRequest)
	}
	if len(trimmedName) > askQueryMaxNameBytes {
		return "", "", fmt.Errorf("%w: name must be at most %d bytes", errInvalidHTTPRequest, askQueryMaxNameBytes)
	}
	trimmedQuestion := strings.TrimSpace(question)
	if trimmedQuestion == "" {
		return "", "", fmt.Errorf("%w: question is required", errInvalidHTTPRequest)
	}
	if len(trimmedQuestion) > askQueryMaxQuestionBytes {
		return "", "", fmt.Errorf("%w: question must be at most %d bytes", errInvalidHTTPRequest, askQueryMaxQuestionBytes)
	}
	return trimmedName, trimmedQuestion, nil
}

func newAskQueryView(query *ports.AskQuery) askQueryView {
	return askQueryView{
		ID:        query.ID,
		TenantID:  query.TenantID,
		Name:      query.Name,
		Question:  query.Question,
		ScopeURN:  query.ScopeURN,
		Model:     query.Model,
		Pinned:    query.Pinned,
		CreatedAt: query.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: query.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func newAskQueryID() string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Sprintf("ask-query-%d", time.Now().UnixNano())
	}
	return "ask-query-" + hex.EncodeToString(random[:])
}

func askQueryStore(store ports.StateStore) ports.AskQueryStore {
	queryStore, ok := store.(ports.AskQueryStore)
	if !ok || isNilInterface(queryStore) {
		return nil
	}
	return queryStore
}
