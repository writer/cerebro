package k8saudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/runtime/adapters"
)

const sourceName = "kubernetes_audit"

type Adapter struct{}

var _ adapters.Adapter = Adapter{}

type payload struct {
	Items json.RawMessage `json:"items"`
}

type event struct {
	AuditID           string            `json:"auditID"`
	Stage             string            `json:"stage"`
	Verb              string            `json:"verb"`
	RequestURI        string            `json:"requestURI"`
	UserAgent         string            `json:"userAgent"`
	SourceIPs         []string          `json:"sourceIPs"`
	Annotations       map[string]string `json:"annotations"`
	RequestReceivedAt time.Time         `json:"requestReceivedTimestamp"`
	StageAt           time.Time         `json:"stageTimestamp"`
	User              userInfo          `json:"user"`
	ImpersonatedUser  userInfo          `json:"impersonatedUser"`
	ObjectRef         objectRef         `json:"objectRef"`
}

type userInfo struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type objectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Subresource string `json:"subresource"`
	APIGroup    string `json:"apiGroup"`
	APIVersion  string `json:"apiVersion"`
}

func (Adapter) Source() string {
	return sourceName
}

func (Adapter) Normalize(_ context.Context, raw []byte) ([]*runtime.RuntimeObservation, error) {
	events, err := decode(raw)
	if err != nil {
		return nil, err
	}
	observations := make([]*runtime.RuntimeObservation, 0, len(events))
	for _, evt := range events {
		observations = append(observations, observationFromEvent(evt))
	}
	return observations, nil
}

func decode(raw []byte) ([]event, error) {
	var list payload
	if err := json.Unmarshal(raw, &list); err == nil {
		if list.Items != nil {
			trimmed := bytes.TrimSpace(list.Items)
			if bytes.Equal(trimmed, []byte("null")) {
				return []event{}, nil
			}
			var items []event
			if err := json.Unmarshal(trimmed, &items); err != nil {
				return nil, fmt.Errorf("decode kubernetes audit list payload: %w", err)
			}
			return items, nil
		}
	}

	var single event
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, fmt.Errorf("decode kubernetes audit payload: %w", err)
	}
	return []event{single}, nil
}

func observationFromEvent(evt event) *runtime.RuntimeObservation {
	observedAt := evt.StageAt
	if observedAt.IsZero() {
		observedAt = evt.RequestReceivedAt
	}
	resourceType := strings.ToLower(evt.ObjectRef.Resource)
	resourceID := objectRefID(evt.ObjectRef)
	tags := make([]string, 0, 2)
	if evt.ObjectRef.Subresource == "exec" {
		tags = append(tags, "kubectl_exec")
	}
	if evt.ObjectRef.Subresource == "attach" {
		tags = append(tags, "kubectl_attach")
	}

	return &runtime.RuntimeObservation{
		ID:           evt.AuditID,
		Kind:         runtime.ObservationKindKubernetesAudit,
		Source:       sourceName,
		ObservedAt:   observedAt,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Namespace:    evt.ObjectRef.Namespace,
		PrincipalID:  evt.User.Username,
		ControlPlane: &runtime.ControlPlaneContext{
			Source:           sourceName,
			Verb:             evt.Verb,
			Stage:            evt.Stage,
			User:             evt.User.Username,
			ImpersonatedUser: evt.ImpersonatedUser.Username,
			UserAgent:        evt.UserAgent,
			RequestURI:       evt.RequestURI,
			Resource:         resourceType,
			Namespace:        evt.ObjectRef.Namespace,
			Name:             evt.ObjectRef.Name,
			Subresource:      evt.ObjectRef.Subresource,
			SourceIPs:        append([]string(nil), evt.SourceIPs...),
			Annotations:      runtime.CloneStringMap(evt.Annotations),
		},
		Tags: tags,
		Metadata: map[string]any{
			"audit_api_group":   evt.ObjectRef.APIGroup,
			"audit_api_version": evt.ObjectRef.APIVersion,
			"user_groups":       append([]string(nil), evt.User.Groups...),
		},
	}
}

func objectRefID(ref objectRef) string {
	if ref.Resource == "" {
		return ""
	}
	parts := []string{strings.ToLower(ref.Resource)}
	if ref.Namespace != "" {
		parts = append(parts, ref.Namespace)
	}
	if ref.Name != "" {
		parts = append(parts, ref.Name)
	}
	if ref.Subresource != "" {
		parts = append(parts, ref.Subresource)
	}
	return strings.Join(parts, ":")
}
