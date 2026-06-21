package sourceplanapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen"
)

const maxPlanRequestBytes = 1 << 20

type Dependencies struct {
	EffectiveTenant func(context.Context, string) (string, error)
	GetDefinition   func(context.Context, string) (connectordefinitions.Definition, error)
	WriteJSON       func(http.ResponseWriter, int, any)
	WriteError      func(http.ResponseWriter, error)
	InvalidRequest  error
}

type planRequest struct {
	Definition           connectordefinitions.Definition `json:"definition"`
	FreshnessExpectation string                          `json:"freshness_expectation,omitempty"`
	HealthPath           string                          `json:"health_path,omitempty"`
	OutputDir            string                          `json:"output_dir,omitempty"`
}

type planResponse struct {
	GeneratedAt string                   `json:"generated_at"`
	Plan        *sourcegen.PromotionPlan `json:"plan"`
}

func HandleDefinitionPlan(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, err := readPlanRequest(r, deps.InvalidRequest)
		if err != nil {
			deps.WriteError(w, err)
			return
		}
		tenantID, err := deps.EffectiveTenant(r.Context(), request.Definition.TenantID)
		if err != nil {
			deps.WriteError(w, err)
			return
		}
		request.Definition.TenantID = tenantID
		writePlan(w, deps, sourcegen.DefinitionRequest{
			Definition:           request.Definition,
			FreshnessExpectation: request.FreshnessExpectation,
			HealthPath:           request.HealthPath,
			OutputDir:            request.OutputDir,
		})
	}
}

func HandleStoredPromotionPlan(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		definitionID := strings.TrimSpace(r.PathValue("definitionID"))
		if definitionID == "" {
			deps.WriteError(w, fmt.Errorf("%w: definition_id is required", deps.InvalidRequest))
			return
		}
		definition, err := deps.GetDefinition(r.Context(), definitionID)
		if err != nil {
			deps.WriteError(w, err)
			return
		}
		writePlan(w, deps, sourcegen.DefinitionRequest{Definition: definition})
	}
}

func readPlanRequest(r *http.Request, invalidRequest error) (planRequest, error) {
	if r == nil || r.Body == nil {
		return planRequest{}, fmt.Errorf("%w: request body is required", invalidRequest)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPlanRequestBytes+1))
	if err != nil {
		return planRequest{}, fmt.Errorf("%w: read request body: %w", invalidRequest, err)
	}
	if len(body) > maxPlanRequestBytes {
		return planRequest{}, fmt.Errorf("%w: request JSON body exceeds maximum size", invalidRequest)
	}
	request := planRequest{}
	if err := json.Unmarshal(body, &request); err == nil && strings.TrimSpace(request.Definition.SourceID) != "" {
		return request, nil
	}
	definition := connectordefinitions.Definition{}
	if err := json.Unmarshal(body, &definition); err != nil {
		return planRequest{}, fmt.Errorf("%w: decode connector definition plan request: %w", invalidRequest, err)
	}
	return planRequest{Definition: definition}, nil
}

func writePlan(w http.ResponseWriter, deps Dependencies, request sourcegen.DefinitionRequest) {
	plan, err := sourcegen.PlanDefinition(request)
	if err != nil {
		deps.WriteError(w, fmt.Errorf("%w: %w", deps.InvalidRequest, err))
		return
	}
	deps.WriteJSON(w, http.StatusOK, planResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Plan:        plan,
	})
}
