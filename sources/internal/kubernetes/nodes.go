package kubernetesinternal

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type clusterInfo struct {
	ClusterID      string `json:"cluster_id"`
	ClusterName    string `json:"cluster_name"`
	ExternalID     string `json:"external_id,omitempty"`
	GitVersion     string `json:"git_version,omitempty"`
	Major          string `json:"major,omitempty"`
	Minor          string `json:"minor,omitempty"`
	Platform       string `json:"platform,omitempty"`
	CloudProvider  string `json:"cloud_provider,omitempty"`
	CloudAccountID string `json:"cloud_account_id,omitempty"`
}

func (s *Source) discoverCluster(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	info, err := s.clusterInfo(ctx, st)
	if err != nil {
		return nil, err
	}
	return parseURNs(clusterURN(st, info.ClusterID))
}

func (s *Source) discoverNodes(ctx context.Context, st settings) ([]sourcecdk.URN, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return nil, err
	}
	items, _, err := listNodes(ctx, client, st.perPage, "")
	if err != nil {
		return nil, err
	}
	urns := make([]string, 0, len(items))
	for _, item := range items {
		urns = append(urns, nodeURN(st, item.Name))
	}
	return parseURNs(urns...)
}

func (s *Source) readCluster(ctx context.Context, st settings, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	info, err := s.clusterInfo(ctx, st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	event, err := s.event(st, "kubernetes-cluster-"+info.ClusterID, "kubernetes.cluster", "kubernetes/cluster/v1", info, clusterAttributes(st, info), s.now())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return sourcecdk.Pull{Events: []*primitives.Event{event}}, nil
}

func (s *Source) readNodes(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	items, next, err := listNodes(ctx, client, st.perPage, cursor.GetOpaque())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(items))
	for _, item := range items {
		payload := nodePayload(item)
		attrs := nodeAttributes(st, item)
		id := "kubernetes-node-" + stableID(st.clusterIdentity()+"/"+item.Name)
		event, err := s.event(st, id, "kubernetes.node", "kubernetes/node/v1", payload, attrs, objectTime(item.CreationTimestamp, s.now()))
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	return pullWithCursor(events, next), nil
}

func (s *Source) clusterInfo(ctx context.Context, st settings) (clusterInfo, error) {
	client, err := s.clientFactory(st)
	if err != nil {
		return clusterInfo{}, err
	}
	version, err := client.Discovery().ServerVersion()
	if err != nil {
		return clusterInfo{}, fmt.Errorf("read kubernetes server version: %w", err)
	}
	clusterName := firstNonEmpty(st.clusterName, st.contextName, st.externalID, "cluster")
	clusterID := firstNonEmpty(st.clusterID, st.externalID)
	if clusterID == "" {
		if ns, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{}); err == nil {
			clusterID = string(ns.UID)
		}
	}
	clusterID = firstNonEmpty(clusterID, stableID(clusterName))
	return clusterInfo{ClusterID: clusterID, ClusterName: clusterName, ExternalID: st.externalID, GitVersion: version.GitVersion, Major: version.Major, Minor: version.Minor, Platform: version.Platform, CloudProvider: st.cloudProvider, CloudAccountID: st.cloudAccountID}, nil
}

func listNodes(ctx context.Context, client clientset, limit int64, cursor string) ([]v1.Node, string, error) {
	out, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: limit, Continue: strings.TrimSpace(cursor)})
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes nodes: %w", err)
	}
	return out.Items, out.Continue, nil
}

func clusterAttributes(st settings, info clusterInfo) map[string]string {
	attrs := map[string]string{"cluster_id": info.ClusterID, "cluster_name": info.ClusterName}
	add(attrs, "external_id", info.ExternalID)
	add(attrs, "cloud_provider", firstNonEmpty(info.CloudProvider, st.cloudProvider))
	add(attrs, "cloud_account_id", firstNonEmpty(info.CloudAccountID, st.cloudAccountID))
	add(attrs, "git_version", info.GitVersion)
	add(attrs, "version_major", info.Major)
	add(attrs, "version_minor", info.Minor)
	add(attrs, "platform", info.Platform)
	return attrs
}

func nodeAttributes(st settings, node v1.Node) map[string]string {
	attrs := resourceAttributes(st, "node", firstNonEmpty(string(node.UID), node.Name), node.Name, "")
	attrs["uid"] = string(node.UID)
	attrs["node_name"] = node.Name
	attrs["ready"] = boolString(nodeReady(node))
	attrs["unschedulable"] = boolString(node.Spec.Unschedulable)
	add(attrs, "provider_id", node.Spec.ProviderID)
	add(attrs, "pod_cidr", node.Spec.PodCIDR)
	add(attrs, "pod_cidrs", strings.Join(node.Spec.PodCIDRs, ","))
	add(attrs, "internal_ip", nodeAddress(node, v1.NodeInternalIP))
	add(attrs, "external_ip", nodeAddress(node, v1.NodeExternalIP))
	add(attrs, "kernel_version", node.Status.NodeInfo.KernelVersion)
	add(attrs, "kubelet_version", node.Status.NodeInfo.KubeletVersion)
	add(attrs, "container_runtime_version", node.Status.NodeInfo.ContainerRuntimeVersion)
	add(attrs, "os_image", node.Status.NodeInfo.OSImage)
	add(attrs, "operating_system", node.Status.NodeInfo.OperatingSystem)
	add(attrs, "architecture", node.Status.NodeInfo.Architecture)
	add(attrs, "labels", jsonAttribute(node.Labels))
	add(attrs, "taints", jsonAttribute(node.Spec.Taints))
	add(attrs, "capacity", jsonAttribute(node.Status.Capacity))
	add(attrs, "allocatable", jsonAttribute(node.Status.Allocatable))
	return attrs
}

func nodePayload(node v1.Node) map[string]any {
	return map[string]any{
		"uid":               string(node.UID),
		"name":              node.Name,
		"provider_id":       node.Spec.ProviderID,
		"unschedulable":     node.Spec.Unschedulable,
		"pod_cidr":          node.Spec.PodCIDR,
		"pod_cidrs":         node.Spec.PodCIDRs,
		"taints":            node.Spec.Taints,
		"labels":            node.Labels,
		"annotations":       node.Annotations,
		"addresses":         node.Status.Addresses,
		"conditions":        node.Status.Conditions,
		"capacity":          node.Status.Capacity,
		"allocatable":       node.Status.Allocatable,
		"node_info":         node.Status.NodeInfo,
		"ready":             nodeReady(node),
		"internal_ip":       nodeAddress(node, v1.NodeInternalIP),
		"external_ip":       nodeAddress(node, v1.NodeExternalIP),
		"kubelet_version":   node.Status.NodeInfo.KubeletVersion,
		"container_runtime": node.Status.NodeInfo.ContainerRuntimeVersion,
	}
}

func nodeReady(node v1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == v1.NodeReady {
			return condition.Status == v1.ConditionTrue
		}
	}
	return false
}

func nodeAddress(node v1.Node, addressType v1.NodeAddressType) string {
	for _, address := range node.Status.Addresses {
		if address.Type == addressType && strings.TrimSpace(address.Address) != "" {
			return strings.TrimSpace(address.Address)
		}
	}
	return ""
}

func clusterURN(st settings, id string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_cluster:%s", url.PathEscape(st.tenantID), url.PathEscape(id))
}

func nodeURN(st settings, name string) string {
	return fmt.Sprintf("urn:cerebro:%s:kubernetes_node:%s:%s", url.PathEscape(st.tenantID), url.PathEscape(st.clusterIdentity()), url.PathEscape(name))
}
