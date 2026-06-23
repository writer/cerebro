package kubernetesinternal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type kubernetesRBACRole struct {
	Kind      string
	Name      string
	Namespace string
	UID       string
	Rules     []rbacv1.PolicyRule
	Created   metav1.Time
}

type kubernetesRBACBinding struct {
	Kind      string
	Name      string
	Namespace string
	UID       string
	RoleRef   rbacv1.RoleRef
	Subjects  []rbacv1.Subject
	Created   metav1.Time
}

type rbacSubjectRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type kubernetesStageCursor struct {
	Stage string `json:"stage,omitempty"`
	Token string `json:"token,omitempty"`
}

func (s *Source) discoverRBACRoles(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	roles, _, err := listRBACRoles(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	clusterRoles, _, err := listRBACClusterRoles(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(roles)+len(clusterRoles))
	for _, item := range roles {
		urns = append(urns, rbacRoleURN(st, "Role", item.Namespace, item.Name))
	}
	for _, item := range clusterRoles {
		urns = append(urns, rbacRoleURN(st, "ClusterRole", "", item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) discoverRBACBindings(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	bindings, _, err := listRBACRoleBindings(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	clusterBindings, _, err := listRBACClusterRoleBindings(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(bindings)+len(clusterBindings))
	for _, item := range bindings {
		urns = append(urns, rbacBindingURN(st, "RoleBinding", item.Namespace, item.Name))
	}
	for _, item := range clusterBindings {
		urns = append(urns, rbacBindingURN(st, "ClusterRoleBinding", "", item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) readRBACRoles(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	state, err := parseKubernetesStageCursor(cursor.GetOpaque(), "role", "rbac_role")
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := []*primitives.Event{}
	switch state.Stage {
	case "role":
		roles, next, err := listRBACRoles(ctx, client, st.perPage, state.Token)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		for _, role := range roles {
			event, err := s.rbacRoleEvent(st, kubernetesRBACRole{Kind: "Role", Name: role.Name, Namespace: role.Namespace, UID: string(role.UID), Rules: role.Rules, Created: role.CreationTimestamp})
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
		if next != "" {
			return pullWithCursor(events, encodeKubernetesStageCursor(kubernetesStageCursor{Stage: "role", Token: next})), nil
		}
		state = kubernetesStageCursor{Stage: "cluster_role"}
		fallthrough
	case "cluster_role":
		clusterRoles, next, err := listRBACClusterRoles(ctx, client, st.perPage, state.Token)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		for _, role := range clusterRoles {
			event, err := s.rbacRoleEvent(st, kubernetesRBACRole{Kind: "ClusterRole", Name: role.Name, UID: string(role.UID), Rules: role.Rules, Created: role.CreationTimestamp})
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
		if next != "" {
			return pullWithCursor(events, encodeKubernetesStageCursor(kubernetesStageCursor{Stage: "cluster_role", Token: next})), nil
		}
	default:
		return sourcecdk.Pull{}, fmt.Errorf("unknown kubernetes rbac_role cursor stage %q", state.Stage)
	}
	return sourcecdk.Pull{Events: events}, nil
}

func (s *Source) readRBACBindings(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	state, err := parseKubernetesStageCursor(cursor.GetOpaque(), "role_binding", "rbac_binding")
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := []*primitives.Event{}
	switch state.Stage {
	case "role_binding":
		bindings, next, err := listRBACRoleBindings(ctx, client, st.perPage, state.Token)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		for _, binding := range bindings {
			event, err := s.rbacBindingEvent(st, kubernetesRBACBinding{Kind: "RoleBinding", Name: binding.Name, Namespace: binding.Namespace, UID: string(binding.UID), RoleRef: binding.RoleRef, Subjects: binding.Subjects, Created: binding.CreationTimestamp})
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
		if next != "" {
			return pullWithCursor(events, encodeKubernetesStageCursor(kubernetesStageCursor{Stage: "role_binding", Token: next})), nil
		}
		state = kubernetesStageCursor{Stage: "cluster_role_binding"}
		fallthrough
	case "cluster_role_binding":
		clusterBindings, next, err := listRBACClusterRoleBindings(ctx, client, st.perPage, state.Token)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		for _, binding := range clusterBindings {
			event, err := s.rbacBindingEvent(st, kubernetesRBACBinding{Kind: "ClusterRoleBinding", Name: binding.Name, UID: string(binding.UID), RoleRef: binding.RoleRef, Subjects: binding.Subjects, Created: binding.CreationTimestamp})
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
		if next != "" {
			return pullWithCursor(events, encodeKubernetesStageCursor(kubernetesStageCursor{Stage: "cluster_role_binding", Token: next})), nil
		}
	default:
		return sourcecdk.Pull{}, fmt.Errorf("unknown kubernetes rbac_binding cursor stage %q", state.Stage)
	}
	return sourcecdk.Pull{Events: events}, nil
}

func (s *Source) rbacRoleEvent(st settings, role kubernetesRBACRole) (*primitives.Event, error) {
	attrs := rbacRoleAttributes(st, role)
	rules := role.Rules
	if rules == nil {
		rules = []rbacv1.PolicyRule{}
	}
	payload := map[string]any{
		"uid":        role.UID,
		"name":       role.Name,
		"namespace":  role.Namespace,
		"role_kind":  role.Kind,
		"role_scope": rbacScope(role.Namespace),
		"rules":      rules,
	}
	id := "kubernetes-rbac-role-" + stableID(st.clusterIdentity()+"/"+role.Kind+"/"+role.Namespace+"/"+role.Name+"/"+role.UID)
	return s.event(st, id, "kubernetes.rbac_role", "kubernetes/rbac_role/v1", payload, attrs, objectTime(role.Created, s.now()))
}

func (s *Source) rbacBindingEvent(st settings, binding kubernetesRBACBinding) (*primitives.Event, error) {
	attrs := rbacBindingAttributes(st, binding)
	payload := map[string]any{
		"uid":           binding.UID,
		"name":          binding.Name,
		"namespace":     binding.Namespace,
		"binding_kind":  binding.Kind,
		"binding_scope": rbacScope(binding.Namespace),
		"role_ref":      binding.RoleRef,
		"subjects":      binding.Subjects,
	}
	id := "kubernetes-rbac-binding-" + stableID(st.clusterIdentity()+"/"+binding.Kind+"/"+binding.Namespace+"/"+binding.Name+"/"+binding.UID)
	return s.event(st, id, "kubernetes.rbac_binding", "kubernetes/rbac_binding/v1", payload, attrs, objectTime(binding.Created, s.now()))
}

func listRBACRoles(ctx context.Context, client clientset, limit int64, cursor string) ([]rbacv1.Role, string, error) {
	out, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes roles: %w", err)
	}
	return out.Items, out.Continue, nil
}

func listRBACClusterRoles(ctx context.Context, client clientset, limit int64, cursor string) ([]rbacv1.ClusterRole, string, error) {
	out, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes cluster roles: %w", err)
	}
	return out.Items, out.Continue, nil
}

func listRBACRoleBindings(ctx context.Context, client clientset, limit int64, cursor string) ([]rbacv1.RoleBinding, string, error) {
	out, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes role bindings: %w", err)
	}
	return out.Items, out.Continue, nil
}

func listRBACClusterRoleBindings(ctx context.Context, client clientset, limit int64, cursor string) ([]rbacv1.ClusterRoleBinding, string, error) {
	out, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes cluster role bindings: %w", err)
	}
	return out.Items, out.Continue, nil
}

func rbacRoleAttributes(st settings, role kubernetesRBACRole) map[string]string {
	attrs := resourceAttributes(st, "rbac_role", firstNonEmpty(role.UID, role.Kind+"/"+role.Namespace+"/"+role.Name), role.Name, role.Namespace)
	attrs["uid"] = role.UID
	attrs["role_kind"] = role.Kind
	attrs["role_name"] = role.Name
	attrs["role_scope"] = rbacScope(role.Namespace)
	attrs["rules"] = strings.Join(rbacRuleSummaries(role.Rules), ";")
	attrs["api_groups"] = strings.Join(rbacRuleValues(role.Rules, func(rule rbacv1.PolicyRule) []string { return rule.APIGroups }), ",")
	attrs["resources"] = strings.Join(rbacRuleValues(role.Rules, func(rule rbacv1.PolicyRule) []string { return rule.Resources }), ",")
	attrs["verbs"] = strings.Join(rbacRuleValues(role.Rules, func(rule rbacv1.PolicyRule) []string { return rule.Verbs }), ",")
	return attrs
}

func rbacBindingAttributes(st settings, binding kubernetesRBACBinding) map[string]string {
	attrs := resourceAttributes(st, "rbac_binding", firstNonEmpty(binding.UID, binding.Kind+"/"+binding.Namespace+"/"+binding.Name), binding.Name, binding.Namespace)
	attrs["uid"] = binding.UID
	attrs["binding_kind"] = binding.Kind
	attrs["binding_name"] = binding.Name
	attrs["binding_scope"] = rbacScope(binding.Namespace)
	attrs["role_api_group"] = binding.RoleRef.APIGroup
	attrs["role_kind"] = binding.RoleRef.Kind
	attrs["role_name"] = binding.RoleRef.Name
	attrs["subject_count"] = strconv.Itoa(len(binding.Subjects))
	attrs["subject_refs"] = rbacSubjectRefsAttribute(binding.Subjects, binding.Namespace)
	attrs["subject_kinds"] = strings.Join(rbacSubjectValues(binding.Subjects, func(subject rbacv1.Subject) string { return subject.Kind }), ",")
	attrs["subject_names"] = strings.Join(rbacSubjectValues(binding.Subjects, func(subject rbacv1.Subject) string {
		return subject.Name
	}), ",")
	return attrs
}

func rbacScope(namespace string) string {
	if strings.TrimSpace(namespace) == "" {
		return "cluster"
	}
	return "namespace"
}

func rbacRuleSummaries(rules []rbacv1.PolicyRule) []string {
	values := make([]string, 0, len(rules))
	for _, rule := range rules {
		values = append(values, fmt.Sprintf("%s:%s:%s", strings.Join(rule.APIGroups, ","), strings.Join(rule.Resources, ","), strings.Join(rule.Verbs, ",")))
	}
	sort.Strings(values)
	return values
}

func rbacRuleValues(rules []rbacv1.PolicyRule, field func(rbacv1.PolicyRule) []string) []string {
	seen := map[string]struct{}{}
	values := []string{}
	for _, rule := range rules {
		for _, value := range field(rule) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

func rbacSubjectRefsAttribute(subjects []rbacv1.Subject, bindingNamespace string) string {
	refs := rbacSubjectRefs(subjects, bindingNamespace)
	raw, _ := json.Marshal(refs)
	return string(raw)
}

func rbacSubjectRefs(subjects []rbacv1.Subject, bindingNamespace string) []rbacSubjectRef {
	values := make([]rbacSubjectRef, 0, len(subjects))
	for _, subject := range subjects {
		namespace := subject.Namespace
		if subject.Kind == "ServiceAccount" {
			namespace = firstNonEmpty(namespace, bindingNamespace, "default")
		}
		ref := rbacSubjectRef{
			Kind: strings.TrimSpace(subject.Kind),
			Name: strings.TrimSpace(subject.Name),
		}
		if strings.TrimSpace(namespace) != "" {
			ref.Namespace = strings.TrimSpace(namespace)
		}
		if ref.Kind == "" || ref.Name == "" {
			continue
		}
		values = append(values, ref)
	}
	sort.Slice(values, func(i int, j int) bool {
		if values[i].Kind != values[j].Kind {
			return values[i].Kind < values[j].Kind
		}
		if values[i].Namespace != values[j].Namespace {
			return values[i].Namespace < values[j].Namespace
		}
		return values[i].Name < values[j].Name
	})
	return values
}

func rbacSubjectValues(subjects []rbacv1.Subject, field func(rbacv1.Subject) string) []string {
	seen := map[string]struct{}{}
	values := []string{}
	for _, subject := range subjects {
		value := strings.TrimSpace(field(subject))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func parseKubernetesStageCursor(raw string, defaultStage string, label string) (kubernetesStageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return kubernetesStageCursor{Stage: defaultStage}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return kubernetesStageCursor{}, fmt.Errorf("decode kubernetes %s cursor: %w", label, err)
	}
	cursor := kubernetesStageCursor{}
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return kubernetesStageCursor{}, fmt.Errorf("parse kubernetes %s cursor: %w", label, err)
	}
	if cursor.Stage == "" {
		cursor.Stage = defaultStage
	}
	return cursor, nil
}

func encodeKubernetesStageCursor(cursor kubernetesStageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func rbacRoleURN(st settings, kind string, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_rbac_role:%s:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(kind), url.PathEscape(firstNonEmpty(namespace, "cluster")), url.PathEscape(name))
}

func rbacBindingURN(st settings, kind string, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_rbac_binding:%s:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(kind), url.PathEscape(firstNonEmpty(namespace, "cluster")), url.PathEscape(name))
}
