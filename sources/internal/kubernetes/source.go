package kubernetesinternal

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	networkingv1client "k8s.io/client-go/kubernetes/typed/networking/v1"
	rbacv1client "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

//go:embed catalog.internal.yaml
var catalogFS embed.FS

const (
	sourceID = "kubernetes"

	familyCluster                 = "cluster"
	familyIngress                 = "ingress"
	familyNamespace               = "namespace"
	familyNode                    = "node"
	familyPod                     = "pod"
	familyService                 = "service"
	familyContainer               = "container"
	familyRBACBinding             = "rbac_binding"
	familyRBACRole                = "rbac_role"
	familyServiceAccount          = "service_account"
	familyWorkload                = "workload"
	familyWorkloadIdentityBinding = "workload_identity_binding"

	defaultFamily   = familyWorkload
	defaultPageSize = 100
	maxPageSize     = 500
)

type clientset interface {
	Discovery() discovery.DiscoveryInterface
	CoreV1() corev1client.CoreV1Interface
	NetworkingV1() networkingv1client.NetworkingV1Interface
	RbacV1() rbacv1client.RbacV1Interface
}

type settings struct {
	tenantID       string
	family         string
	kubeconfigPath string
	contextName    string
	inCluster      bool
	clusterID      string
	clusterName    string
	externalID     string
	cloudProvider  string
	cloudAccountID string
	perPage        int64
}

// Source is the Kubernetes inventory source.
type Source struct {
	spec          *cerebrov1.SourceSpec
	families      *sourcecdk.FamilyEngine[settings]
	clientFactory func(settings) (clientset, error)
	now           func() time.Time
}

// New constructs the Kubernetes source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, now: func() time.Time { return time.Now().UTC() }}
	source.clientFactory = source.defaultClientset
	families, err := source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	source.families = families
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

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(st settings) string { return st.family },
		sourcecdk.Family[settings]{Name: familyCluster, Check: s.check, Discover: s.discoverCluster, Read: s.readCluster},
		sourcecdk.Family[settings]{Name: familyIngress, Check: s.check, Discover: s.discoverIngresses, Read: s.readIngresses},
		sourcecdk.Family[settings]{Name: familyNamespace, Check: s.check, Discover: s.discoverNamespaces, Read: s.readNamespaces},
		sourcecdk.Family[settings]{Name: familyNode, Check: s.check, Discover: s.discoverNodes, Read: s.readNodes},
		sourcecdk.Family[settings]{Name: familyPod, Check: s.check, Discover: s.discoverPods, Read: s.readPods},
		sourcecdk.Family[settings]{Name: familyService, Check: s.check, Discover: s.discoverServices, Read: s.readServices},
		sourcecdk.Family[settings]{Name: familyContainer, Check: s.check, Discover: s.discoverPods, Read: s.readContainers},
		sourcecdk.Family[settings]{Name: familyRBACRole, Check: s.check, Discover: s.discoverRBACRoles, Read: s.readRBACRoles},
		sourcecdk.Family[settings]{Name: familyRBACBinding, Check: s.check, Discover: s.discoverRBACBindings, Read: s.readRBACBindings},
		sourcecdk.Family[settings]{Name: familyServiceAccount, Check: s.check, Discover: s.discoverServiceAccounts, Read: s.readServiceAccounts},
		sourcecdk.Family[settings]{Name: familyWorkload, Check: s.check, Discover: s.discoverPods, Read: s.readWorkloads},
		sourcecdk.Family[settings]{Name: familyWorkloadIdentityBinding, Check: s.check, Discover: s.discoverServiceAccounts, Read: s.readWorkloadIdentityBindings},
	)
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	st := settings{
		tenantID:       firstNonEmpty(sourcecdk.ConfigValue(cfg, "tenant_id"), sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey)),
		family:         strings.TrimSpace(sourcecdk.ConfigValue(cfg, "family")),
		kubeconfigPath: strings.TrimSpace(firstNonEmpty(sourcecdk.ConfigValue(cfg, "kubeconfig_path"), sourcecdk.ConfigValue(cfg, "kubeconfig"))),
		contextName:    strings.TrimSpace(sourcecdk.ConfigValue(cfg, "context")),
		clusterID:      strings.TrimSpace(sourcecdk.ConfigValue(cfg, "cluster_id")),
		clusterName:    strings.TrimSpace(sourcecdk.ConfigValue(cfg, "cluster_name")),
		externalID:     strings.TrimSpace(sourcecdk.ConfigValue(cfg, "external_id")),
		cloudProvider:  normalizeIdentifier(firstNonEmpty(sourcecdk.ConfigValue(cfg, "cloud_provider"), sourcecdk.ConfigValue(cfg, "provider"))),
		cloudAccountID: strings.TrimSpace(firstNonEmpty(sourcecdk.ConfigValue(cfg, "cloud_account_id"), sourcecdk.ConfigValue(cfg, "account_id"), sourcecdk.ConfigValue(cfg, "project_id"), sourcecdk.ConfigValue(cfg, "subscription_id"))),
		perPage:        defaultPageSize,
	}
	if st.family == "" {
		st.family = defaultFamily
	}
	switch st.family {
	case familyCluster, familyIngress, familyNamespace, familyNode, familyPod, familyService, familyContainer, familyRBACBinding, familyRBACRole, familyServiceAccount, familyWorkload, familyWorkloadIdentityBinding:
	default:
		return st, fmt.Errorf("kubernetes family must be one of cluster, ingress, namespace, node, pod, service, container, rbac_binding, rbac_role, service_account, workload, or workload_identity_binding")
	}
	if st.tenantID == "" {
		return st, fmt.Errorf("kubernetes tenant_id is required")
	}
	st.inCluster = parseBool(sourcecdk.ConfigValue(cfg, "in_cluster"))
	if !st.inCluster && st.kubeconfigPath == "" {
		return st, fmt.Errorf("kubernetes kubeconfig_path is required unless in_cluster=true")
	}
	if raw := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "per_page")); raw != "" {
		perPage, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return st, fmt.Errorf("parse kubernetes per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return st, fmt.Errorf("kubernetes per_page must be between 1 and %d", maxPageSize)
		}
		st.perPage = perPage
	}
	return st, nil
}

func (s *Source) defaultClientset(st settings) (clientset, error) {
	var cfg *rest.Config
	var err error
	if st.inCluster {
		cfg, err = rest.InClusterConfig()
	} else {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: st.kubeconfigPath}
		overrides := &clientcmd.ConfigOverrides{CurrentContext: st.contextName}
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("load kubernetes client config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	return client, nil
}

func (s *Source) check(_ context.Context, st settings) error {
	client, err := s.clientFactory(st)
	if err != nil {
		return err
	}
	if _, err := client.Discovery().ServerVersion(); err != nil {
		return fmt.Errorf("read kubernetes server version: %w", err)
	}
	return nil
}

func (s *Source) event(st settings, id string, kind string, schemaRef string, payload any, attrs map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal %s payload: %w", kind, err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   st.tenantID,
		SourceId:   sourceID,
		Kind:       kind,
		SchemaRef:  schemaRef,
		Payload:    raw,
		Attributes: compact(attrs),
		OccurredAt: timestamppb.New(occurredAt.UTC()),
	}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, err
	}
	return event, nil
}

func resourceAttributes(st settings, resourceType string, resourceID string, resourceName string, namespace string) map[string]string {
	attrs := map[string]string{
		"cluster_id":    st.clusterIdentity(),
		"cluster_name":  st.displayClusterName(),
		"resource_id":   resourceID,
		"resource_name": resourceName,
		"resource_type": resourceType,
	}
	add(attrs, "namespace", namespace)
	add(attrs, "external_id", st.externalID)
	add(attrs, "cloud_provider", st.cloudProvider)
	add(attrs, "cloud_account_id", st.cloudAccountID)
	return attrs
}

func pullWithCursor(events []*primitives.Event, next string) sourcecdk.Pull {
	pull := sourcecdk.Pull{Events: events}
	if strings.TrimSpace(next) != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{CursorOpaque: next}
	}
	return pull
}

func (st settings) clusterIdentity() string {
	return firstNonEmpty(st.clusterID, st.externalID, scopedClusterID(st.cloudAccountID, st.clusterName), st.clusterName, st.contextName, "cluster")
}

func (st settings) displayClusterName() string {
	return firstNonEmpty(st.clusterName, st.contextName, st.externalID, st.clusterID, "cluster")
}

func scopedClusterID(accountID string, clusterName string) string {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(clusterName) == "" {
		return ""
	}
	return strings.TrimSpace(accountID) + ":" + strings.TrimSpace(clusterName)
}

func parseURNs(raw ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(raw))
	for _, value := range raw {
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func objectTime(value metav1.Time, fallback time.Time) time.Time {
	if !value.IsZero() {
		return value.UTC()
	}
	return fallback.UTC()
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.internal.yaml")
}

func sortedUnique(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func add(attrs map[string]string, key string, value string) {
	if value = strings.TrimSpace(value); value != "" {
		attrs[key] = value
	}
}

func jsonAttribute(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}

func stringPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func compact(attrs map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attrs {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			out[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func clone(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		out[key] = value
	}
	return out
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizeIdentifier(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	return value
}
