package kubernetesinternal

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Source) discoverIngresses(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	items, _, err := listIngresses(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(items))
	for _, item := range items {
		urns = append(urns, ingressURN(st, item.Namespace, item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) discoverNamespaces(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	items, _, err := listNamespaces(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(items))
	for _, item := range items {
		urns = append(urns, namespaceURN(st, string(item.UID), item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) readIngresses(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listIngresses(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		payload := ingressPayload(item)
		attrs := ingressAttributes(st, item)
		id := "kubernetes-ingress-" + stableID(st.clusterIdentity()+"/"+item.Namespace+"/"+item.Name)
		event, err := s.event(st, id, "kubernetes.ingress", "kubernetes/ingress/v1", payload, attrs, objectTime(item.CreationTimestamp, s.now()))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	return pullWithCursor(events, next), nil
}

func (s *Source) readNamespaces(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listNamespaces(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		payload := map[string]any{"uid": string(item.UID), "name": item.Name, "status": string(item.Status.Phase)}
		attrs := resourceAttributes(st, "namespace", string(item.UID), item.Name, item.Name)
		attrs["namespace"] = item.Name
		event, err := s.event(st, "kubernetes-namespace-"+string(item.UID), "kubernetes.namespace", "kubernetes/namespace/v1", payload, attrs, objectTime(item.CreationTimestamp, s.now()))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	return pullWithCursor(events, next), nil
}

func listNamespaces(ctx context.Context, client clientset, limit int64, cursor string) ([]v1.Namespace, string, error) {
	out, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes namespaces: %w", err)
	}
	return out.Items, out.Continue, nil
}

func listIngresses(ctx context.Context, client clientset, limit int64, cursor string) ([]networkingv1.Ingress, string, error) {
	out, err := client.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes ingresses: %w", err)
	}
	return out.Items, out.Continue, nil
}

func ingressAttributes(st settings, ingress networkingv1.Ingress) map[string]string {
	attrs := resourceAttributes(st, "ingress", firstNonEmpty(string(ingress.UID), ingress.Namespace+"/"+ingress.Name), ingress.Name, ingress.Namespace)
	attrs["uid"] = string(ingress.UID)
	attrs["ingress_name"] = ingress.Name
	add(attrs, "ingress_class_name", stringPointerValue(ingress.Spec.IngressClassName))
	add(attrs, "hosts", strings.Join(ingressHosts(ingress), ","))
	add(attrs, "tls_hosts", strings.Join(ingressTLSHosts(ingress), ","))
	add(attrs, "tls_secret_names", strings.Join(ingressTLSSecretNames(ingress), ","))
	add(attrs, "backend_services", strings.Join(ingressBackendServices(ingress), ","))
	add(attrs, "load_balancer_ips", strings.Join(ingressLoadBalancerIPs(ingress), ","))
	add(attrs, "load_balancer_hostnames", strings.Join(ingressLoadBalancerHostnames(ingress), ","))
	add(attrs, "rules", jsonAttribute(ingressRuleSummaries(ingress)))
	return attrs
}

func ingressPayload(ingress networkingv1.Ingress) map[string]any {
	return map[string]any{
		"uid":                     string(ingress.UID),
		"name":                    ingress.Name,
		"namespace":               ingress.Namespace,
		"ingress_class_name":      ingress.Spec.IngressClassName,
		"rules":                   ingressPayloadRules(ingress.Spec.Rules),
		"tls":                     ingress.Spec.TLS,
		"default_backend":         ingress.Spec.DefaultBackend,
		"load_balancer_ingress":   ingress.Status.LoadBalancer.Ingress,
		"hosts":                   ingressHosts(ingress),
		"tls_hosts":               ingressTLSHosts(ingress),
		"backend_services":        ingressBackendServices(ingress),
		"load_balancer_ips":       ingressLoadBalancerIPs(ingress),
		"load_balancer_hostnames": ingressLoadBalancerHostnames(ingress),
		"labels":                  ingress.Labels,
		"annotations":             ingress.Annotations,
	}
}

func ingressPayloadRules(rules []networkingv1.IngressRule) []networkingv1.IngressRule {
	if rules == nil {
		return []networkingv1.IngressRule{}
	}
	return rules
}

func ingressHosts(ingress networkingv1.Ingress) []string {
	values := []string{}
	for _, rule := range ingress.Spec.Rules {
		values = append(values, rule.Host)
	}
	return sortedUnique(values)
}

func ingressTLSHosts(ingress networkingv1.Ingress) []string {
	values := []string{}
	for _, tls := range ingress.Spec.TLS {
		values = append(values, tls.Hosts...)
	}
	return sortedUnique(values)
}

func ingressTLSSecretNames(ingress networkingv1.Ingress) []string {
	values := []string{}
	for _, tls := range ingress.Spec.TLS {
		values = append(values, tls.SecretName)
	}
	return sortedUnique(values)
}

func ingressBackendServices(ingress networkingv1.Ingress) []string {
	values := []string{}
	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		values = append(values, ingressBackendServiceName(*ingress.Spec.DefaultBackend.Service))
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			values = append(values, ingressBackendServiceName(*path.Backend.Service))
		}
	}
	return sortedUnique(values)
}

func ingressBackendServiceName(service networkingv1.IngressServiceBackend) string {
	port := service.Port.Name
	if port == "" && service.Port.Number != 0 {
		port = strconv.Itoa(int(service.Port.Number))
	}
	return strings.Trim(service.Name+":"+port, ":")
}

func ingressLoadBalancerIPs(ingress networkingv1.Ingress) []string {
	values := []string{}
	for _, item := range ingress.Status.LoadBalancer.Ingress {
		values = append(values, item.IP)
	}
	return sortedUnique(values)
}

func ingressLoadBalancerHostnames(ingress networkingv1.Ingress) []string {
	values := []string{}
	for _, item := range ingress.Status.LoadBalancer.Ingress {
		values = append(values, item.Hostname)
	}
	return sortedUnique(values)
}

func ingressRuleSummaries(ingress networkingv1.Ingress) []string {
	values := []string{}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		host := firstNonEmpty(rule.Host, "*")
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			values = append(values, host+":"+path.Path+"->"+ingressBackendServiceName(*path.Backend.Service))
		}
	}
	return sortedUnique(values)
}

func ingressURN(st settings, namespace string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_ingress:%s:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(namespace), url.PathEscape(name))
}

func namespaceURN(st settings, uid string, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_namespace:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(firstNonEmpty(uid, name)))
}
