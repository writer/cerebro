package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/gcpcloud"
)

type certificateManagerPageResponse = gcpcloud.CertificateManagerPageResponse
type vpcAccessPageResponse = gcpcloud.VPCAccessPageResponse
type pubSubPageResponse = gcpcloud.PubSubPageResponse

type computeAggregatedListResponse struct {
	Items         map[string]computeScopedResources `json:"items"`
	NextPageToken string                            `json:"nextPageToken"`
}

type computeScopedResources struct {
	Addresses               []json.RawMessage `json:"addresses"`
	BackendServices         []json.RawMessage `json:"backendServices"`
	Disks                   []json.RawMessage `json:"disks"`
	ForwardingRules         []json.RawMessage `json:"forwardingRules"`
	HealthChecks            []json.RawMessage `json:"healthChecks"`
	Instances               []json.RawMessage `json:"instances"`
	InstanceGroups          []json.RawMessage `json:"instanceGroups"`
	InstanceGroupMgrs       []json.RawMessage `json:"instanceGroupManagers"`
	InstanceTemplates       []json.RawMessage `json:"instanceTemplates"`
	InterconnectAttachments []json.RawMessage `json:"interconnectAttachments"`
	NetworkEndpointGroups   []json.RawMessage `json:"networkEndpointGroups"`
	Routers                 []json.RawMessage `json:"routers"`
	SecurityPolicies        []json.RawMessage `json:"securityPolicies"`
	SSLCertificates         []json.RawMessage `json:"sslCertificates"`
	SSLPolicies             []json.RawMessage `json:"sslPolicies"`
	Subnetworks             []json.RawMessage `json:"subnetworks"`
	TargetTCPProxies        []json.RawMessage `json:"targetTcpProxies"`
	TargetHTTPProxies       []json.RawMessage `json:"targetHttpProxies"`
	TargetHTTPSProxies      []json.RawMessage `json:"targetHttpsProxies"`
	TargetVPNGateways       []json.RawMessage `json:"targetVpnGateways"`
	URLMaps                 []json.RawMessage `json:"urlMaps"`
	VPNGateways             []json.RawMessage `json:"vpnGateways"`
	VPNTunnels              []json.RawMessage `json:"vpnTunnels"`
	computeScopedSecurityResources
}

type computeScopedSecurityResources struct {
	FirewallPolicies []json.RawMessage `json:"firewallPolicies"`
	PacketMirrorings []json.RawMessage `json:"packetMirrorings"`
}

type assetMetadataRecord struct {
	Name        string            `json:"name"`
	AssetType   string            `json:"assetType"`
	Project     string            `json:"project"`
	DisplayName string            `json:"displayName"`
	Description string            `json:"description"`
	Location    string            `json:"location"`
	Labels      map[string]string `json:"labels"`
	raw         json.RawMessage
}

type computeInstanceRecord = gcpcloud.ComputeInstanceRecord
type firewallRecord = gcpcloud.ComputeFirewallRecord
type auditRecord = gcpcloud.AuditRecord

func listAssetMetadata(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]assetMetadataRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + ":searchAllResources"
	if err := getJSON(ctx, source, settings, cloudAssetBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Results, "gcp asset metadata", func(record *assetMetadataRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listCertificateManagerCertificates(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerCertificateRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response certificateManagerPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/certificates"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Certificates, "gcp certificate manager certificate", gcpcloud.SaveRawField[gcpcloud.CertificateManagerCertificateRecord])
	return records, response.NextPageToken, err
}

func listCertificateManagerCertificateMaps(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerCertificateMapRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response certificateManagerPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/certificateMaps"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.CertificateMaps, "gcp certificate manager certificate map", gcpcloud.SaveRawField[gcpcloud.CertificateManagerCertificateMapRecord])
	return records, response.NextPageToken, err
}

func listCertificateManagerCertificateMapEntries(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerCertificateMapEntryRecord, string, error) {
	maps, next, err := listCertificateManagerCertificateMaps(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.CertificateManagerCertificateMapEntryRecord, 0)
	for _, certificateMap := range maps {
		if strings.TrimSpace(certificateMap.Name) == "" {
			continue
		}
		entries, err := gcpcloud.CollectPages(func(entryPageToken string) ([]gcpcloud.CertificateManagerCertificateMapEntryRecord, string, error) {
			query := url.Values{"pageSize": {strconv.Itoa(limit)}}
			gcpcloud.AddPageToken(query, entryPageToken)
			if strings.TrimSpace(settings.filter) != "" {
				query.Set("filter", settings.filter)
			}
			var response certificateManagerPageResponse
			path := "/v1/" + gcpcloud.EscapePathSegments(certificateMap.Name) + "/certificateMapEntries"
			if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
				return nil, "", err
			}
			entries, err := gcpcloud.DecodeRecords(response.CertificateMapEntries, "gcp certificate manager certificate map entry", func(record *gcpcloud.CertificateManagerCertificateMapEntryRecord, raw json.RawMessage) {
				record.CertificateMap = certificateMap.Name
				record.Raw = append(json.RawMessage(nil), raw...)
			})
			return entries, response.NextPageToken, err
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, entries...)
	}
	return records, next, nil
}

func listCertificateManagerDNSAuthorizations(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerDNSAuthorizationRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response certificateManagerPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/dnsAuthorizations"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.DNSAuthorizations, "gcp certificate manager dns authorization", gcpcloud.SaveRawField[gcpcloud.CertificateManagerDNSAuthorizationRecord])
	return records, response.NextPageToken, err
}

func listComputeInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]computeInstanceRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response computeAggregatedListResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/aggregated/instances"
	if err := getComputeJSON(ctx, source, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	rawRecords := make([]json.RawMessage, 0)
	for scope, scoped := range response.Items {
		for _, raw := range scoped.Instances {
			if len(raw) == 0 {
				continue
			}
			rawRecords = append(rawRecords, raw)
			if scope != "" && !bytes.Contains(raw, []byte(`"zone"`)) {
				var withZone map[string]any
				if err := json.Unmarshal(raw, &withZone); err == nil {
					withZone["zone"] = scope
					if patched, err := json.Marshal(withZone); err == nil {
						rawRecords[len(rawRecords)-1] = patched
					}
				}
			}
		}
	}
	records, err := gcpcloud.DecodeRecords(rawRecords, "gcp compute instance", gcpcloud.SaveRawField[computeInstanceRecord])
	return records, response.NextPageToken, err
}

func computeAggregatedLister[T any](collection, label string, selectRecords func(computeScopedResources) []json.RawMessage, scopeField string, extraQuery url.Values) func(context.Context, *Source, settings, string, int) ([]T, string, error) {
	return func(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]T, string, error) {
		return listComputeAggregatedRecords[T](ctx, source, settings, pageToken, limit, collection, label, selectRecords, scopeField, extraQuery)
	}
}

func computeGlobalLister[T any](collection, label string, extraQuery url.Values) func(context.Context, *Source, settings, string, int) ([]T, string, error) {
	return func(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]T, string, error) {
		query := url.Values{"maxResults": {strconv.Itoa(limit)}}
		for key, values := range extraQuery {
			query[key] = values
		}
		gcpcloud.AddPageToken(query, pageToken)
		var response pageResponse
		path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/global/" + collection
		if err := getComputeJSON(ctx, source, settings, path, query, &response); err != nil {
			return nil, "", err
		}
		records, err := gcpcloud.DecodeRecords(response.Items, label, gcpcloud.SaveRawField[T])
		return records, response.NextPageToken, err
	}
}

var (
	listComputeBackendServices, listComputeBackendBuckets                                                              = computeAggregatedLister[gcpcloud.ComputeBackendServiceRecord]("backendServices", "gcp compute backend service", func(scoped computeScopedResources) []json.RawMessage { return scoped.BackendServices }, "", nil), computeGlobalLister[gcpcloud.ComputeBackendBucketRecord]("backendBuckets", "gcp compute backend bucket", url.Values{"returnPartialSuccess": {"true"}})
	listComputeAddresses, listComputeSecurityPolicies, listComputeNetworkFirewallPolicies, listComputePacketMirrorings = computeAggregatedLister[gcpcloud.ComputeAddressRecord]("addresses", "gcp compute address", func(scoped computeScopedResources) []json.RawMessage { return scoped.Addresses }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeSecurityPolicyRecord]("securityPolicies", "gcp compute security policy", func(scoped computeScopedResources) []json.RawMessage { return scoped.SecurityPolicies }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeNetworkFirewallPolicyRecord]("firewallPolicies", "gcp compute network firewall policy", func(scoped computeScopedResources) []json.RawMessage { return scoped.FirewallPolicies }, "region", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputePacketMirroringRecord]("packetMirrorings", "gcp compute packet mirroring", func(scoped computeScopedResources) []json.RawMessage { return scoped.PacketMirrorings }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeSSLCertificates, listComputeSSLPolicies                                                                 = computeAggregatedLister[gcpcloud.ComputeSSLCertificateRecord]("sslCertificates", "gcp compute ssl certificate", func(scoped computeScopedResources) []json.RawMessage { return scoped.SSLCertificates }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeSSLPolicyRecord]("sslPolicies", "gcp compute ssl policy", func(scoped computeScopedResources) []json.RawMessage { return scoped.SSLPolicies }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeTargetGRPCProxies, listComputeTargetHTTPProxies                                                         = computeGlobalLister[gcpcloud.ComputeTargetGRPCProxyRecord]("targetGrpcProxies", "gcp compute target grpc proxy", nil), computeAggregatedLister[gcpcloud.ComputeTargetHTTPProxyRecord]("targetHttpProxies", "gcp compute target http proxy", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetHTTPProxies }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeTargetHTTPSProxies, listComputeTargetSSLProxies                                                         = computeAggregatedLister[gcpcloud.ComputeTargetHTTPSProxyRecord]("targetHttpsProxies", "gcp compute target https proxy", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetHTTPSProxies }, "", url.Values{"returnPartialSuccess": {"true"}}), computeGlobalLister[gcpcloud.ComputeTargetSSLProxyRecord]("targetSslProxies", "gcp compute target ssl proxy", nil)
	listComputeTargetTCPProxies, listComputeHealthChecks                                                               = computeAggregatedLister[gcpcloud.ComputeTargetTCPProxyRecord]("targetTcpProxies", "gcp compute target tcp proxy", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetTCPProxies }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeHealthCheckRecord]("healthChecks", "gcp compute health check", func(scoped computeScopedResources) []json.RawMessage { return scoped.HealthChecks }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeInstanceGroups, listComputeInstanceGroupManagers                                                        = computeAggregatedLister[gcpcloud.ComputeInstanceGroupRecord]("instanceGroups", "gcp compute instance group", func(scoped computeScopedResources) []json.RawMessage { return scoped.InstanceGroups }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeInstanceGroupManagerRecord]("instanceGroupManagers", "gcp compute instance group manager", func(scoped computeScopedResources) []json.RawMessage { return scoped.InstanceGroupMgrs }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeInstanceTemplates, listComputeNetworkEndpointGroups                                                     = computeAggregatedLister[gcpcloud.ComputeInstanceTemplateRecord]("instanceTemplates", "gcp compute instance template", func(scoped computeScopedResources) []json.RawMessage { return scoped.InstanceTemplates }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeNetworkEndpointGroupRecord]("networkEndpointGroups", "gcp compute network endpoint group", func(scoped computeScopedResources) []json.RawMessage { return scoped.NetworkEndpointGroups }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeInterconnectAttachments, listComputeExternalVPNGateways, listComputeInterconnects, listComputeRouters   = computeAggregatedLister[gcpcloud.ComputeInterconnectAttachmentRecord]("interconnectAttachments", "gcp compute interconnect attachment", func(scoped computeScopedResources) []json.RawMessage { return scoped.InterconnectAttachments }, "", url.Values{"returnPartialSuccess": {"true"}}), computeGlobalLister[gcpcloud.ComputeExternalVPNGatewayRecord]("externalVpnGateways", "gcp compute external vpn gateway", url.Values{"returnPartialSuccess": {"true"}}), computeGlobalLister[gcpcloud.ComputeInterconnectRecord]("interconnects", "gcp compute interconnect", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeRouterRecord]("routers", "gcp compute router", func(scoped computeScopedResources) []json.RawMessage { return scoped.Routers }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeTargetVPNGateways, listComputeVPNGateways                                                               = computeAggregatedLister[gcpcloud.ComputeTargetVPNGatewayRecord]("targetVpnGateways", "gcp compute target vpn gateway", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetVPNGateways }, "region", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeVPNGatewayRecord]("vpnGateways", "gcp compute vpn gateway", func(scoped computeScopedResources) []json.RawMessage { return scoped.VPNGateways }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeURLMaps, listComputeSubnetworks, listComputeForwardingRules                                             = computeAggregatedLister[gcpcloud.ComputeURLMapRecord]("urlMaps", "gcp compute url map", func(scoped computeScopedResources) []json.RawMessage { return scoped.URLMaps }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeSubnetworkRecord]("subnetworks", "gcp compute subnetwork", func(scoped computeScopedResources) []json.RawMessage { return scoped.Subnetworks }, "region", nil), computeAggregatedLister[gcpcloud.ComputeForwardingRuleRecord]("forwardingRules", "gcp compute forwarding rule", func(scoped computeScopedResources) []json.RawMessage { return scoped.ForwardingRules }, "", nil)
	listComputeDisks, listComputeNetworks, listComputeRoutes, listComputeVPNTunnels                                    = computeAggregatedLister[gcpcloud.ComputeDiskRecord]("disks", "gcp compute disk", func(scoped computeScopedResources) []json.RawMessage { return scoped.Disks }, "", nil), computeGlobalLister[gcpcloud.ComputeNetworkRecord]("networks", "gcp compute network", nil), computeGlobalLister[gcpcloud.ComputeRouteRecord]("routes", "gcp compute route", nil), computeAggregatedLister[gcpcloud.ComputeVPNTunnelRecord]("vpnTunnels", "gcp compute vpn tunnel", func(scoped computeScopedResources) []json.RawMessage { return scoped.VPNTunnels }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeFirewalls                                                                                               = computeGlobalLister[firewallRecord]("firewalls", "gcp compute firewall", nil)
)

func listComputeAggregatedRecords[T any](ctx context.Context, source *Source, settings settings, pageToken string, limit int, collection string, label string, selectRecords func(computeScopedResources) []json.RawMessage, scopeField string, extraQuery url.Values) ([]T, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	for key, values := range extraQuery {
		query[key] = append(query[key], values...)
	}
	gcpcloud.AddPageToken(query, pageToken)
	var response computeAggregatedListResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/aggregated/" + collection
	if err := getComputeJSON(ctx, source, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(gcpcloud.ComputeAggregatedRawRecords(response.Items, selectRecords, scopeField), label, gcpcloud.SaveRawField[T])
	return records, response.NextPageToken, err
}

func listDNSManagedZones(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.DNSManagedZoneRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/dns/v1/projects/" + url.PathEscape(settings.projectID) + "/managedZones"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, dnsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.ManagedZones, "gcp dns managed zone", gcpcloud.SaveRawField[gcpcloud.DNSManagedZoneRecord])
	return records, response.NextPageToken, err
}

func listDNSRecordSets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.DNSRecordSetRecord, string, error) {
	parentToken, startIndex, childToken, _, err := sourcecdk.DecodeChildPageCursor("gcp", familyDNSRecordSet, pageToken)
	if err != nil {
		return nil, "", err
	}
	zones, next, err := listDNSManagedZones(ctx, source, settings, parentToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.DNSRecordSetRecord, 0)
	for index := startIndex; index < len(zones); index++ {
		zone := zones[index]
		if strings.TrimSpace(zone.Name) == "" {
			childToken = ""
			continue
		}
		query := url.Values{"maxResults": {strconv.Itoa(limit)}}
		gcpcloud.AddPageToken(query, childToken)
		var response pageResponse
		path := "/dns/v1/projects/" + url.PathEscape(settings.projectID) + "/managedZones/" + url.PathEscape(zone.Name) + "/rrsets"
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, dnsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
			return nil, "", err
		}
		recordSets, err := gcpcloud.DecodeRecords(response.RRSets, "gcp dns record set", func(record *gcpcloud.DNSRecordSetRecord, raw json.RawMessage) {
			record.ManagedZoneName = zone.Name
			record.ManagedZoneDNSName = zone.DNSName
			record.ManagedZoneVisibility = zone.Visibility
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, recordSets...)
		if response.NextPageToken != "" {
			return records, sourcecdk.EncodeChildPageCursor("gcp", familyDNSRecordSet, parentToken, index, response.NextPageToken), nil
		}
		childToken = ""
		if len(records) != 0 {
			return records, sourcecdk.NextChildPageCursor("gcp", familyDNSRecordSet, parentToken, next, index+1, len(zones)), nil
		}
	}
	return records, next, nil
}

func listGKEClusters(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]gcpcloud.GKEClusterRecord, string, error) {
	query := url.Values{}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/-/clusters"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, containerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Clusters, "gcp gke cluster", gcpcloud.SaveRawField[gcpcloud.GKEClusterRecord])
	return records, response.NextPageToken, err
}

func listGKENodePools(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.GKENodePoolRecord, string, error) {
	clusters, next, err := listGKEClusters(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.GKENodePoolRecord, 0)
	for _, cluster := range clusters {
		clusterName := gcpcloud.LastPathSegment(cluster.Name)
		if clusterName == "" {
			continue
		}
		location := firstNonEmpty(cluster.Location, gcpcloud.LocationFromResourceName(cluster.SelfLink), settings.location)
		var response pageResponse
		path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/clusters/" + url.PathEscape(clusterName) + "/nodePools"
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, containerBaseURL, http.MethodGet, path, nil, nil, &response)); err != nil {
			return nil, "", err
		}
		nodePools, err := gcpcloud.DecodeRecords(response.NodePools, "gcp gke node pool", func(record *gcpcloud.GKENodePoolRecord, raw json.RawMessage) {
			record.ClusterName = clusterName
			record.ClusterLocation = location
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, nodePools...)
	}
	return records, next, nil
}

func listCloudIDSEndpoints(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudIDSEndpointRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/endpoints"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, idsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Endpoints, "gcp cloud ids endpoint", gcpcloud.SaveRawField[gcpcloud.CloudIDSEndpointRecord])
	if err != nil || len(records) == 0 {
		return records, response.NextPageToken, err
	}
	sinks, sinkErr := gcpcloud.CollectPages(func(pageToken string) ([]gcpcloud.LoggingSinkRecord, string, error) {
		return listLoggingSinks(ctx, source, settings, pageToken, settings.perPage)
	})
	if sinkErr != nil && gcpcloud.OptionalEnrichmentErr(sinkErr) != nil {
		return nil, "", sinkErr
	}
	gcpcloud.AttachCloudIDSLoggingSinks(records, sinks)
	return records, response.NextPageToken, nil
}

func listCloudRunServices(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudRunServiceRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/locations/-/services"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, runBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Services, "gcp cloud run service", gcpcloud.SaveRawField[gcpcloud.CloudRunServiceRecord])
	return records, response.NextPageToken, err
}

func listCloudRunRevisions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudRunRevisionRecord, string, error) {
	parentToken, startIndex, childToken, _, err := sourcecdk.DecodeChildPageCursor("gcp", familyCloudRunRevision, pageToken)
	if err != nil {
		return nil, "", err
	}
	services, next, err := listCloudRunServices(ctx, source, settings, parentToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.CloudRunRevisionRecord, 0)
	for index := startIndex; index < len(services); index++ {
		service := services[index]
		if strings.TrimSpace(service.Name) == "" {
			childToken = ""
			continue
		}
		query := url.Values{"pageSize": {strconv.Itoa(limit)}}
		gcpcloud.AddPageToken(query, childToken)
		var response pageResponse
		path := "/v2/" + gcpcloud.EscapePathSegments(service.Name) + "/revisions"
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, runBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
			return nil, "", err
		}
		revisions, err := gcpcloud.DecodeRecords(response.Revisions, "gcp cloud run revision", func(record *gcpcloud.CloudRunRevisionRecord, raw json.RawMessage) {
			record.ServiceName = service.Name
			record.ServiceLocation = gcpcloud.LocationFromResourceName(service.Name)
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, revisions...)
		if response.NextPageToken != "" {
			return records, sourcecdk.EncodeChildPageCursor("gcp", familyCloudRunRevision, parentToken, index, response.NextPageToken), nil
		}
		childToken = ""
		if len(records) != 0 {
			return records, sourcecdk.NextChildPageCursor("gcp", familyCloudRunRevision, parentToken, next, index+1, len(services)), nil
		}
	}
	return records, next, nil
}

func listCloudFunctions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudFunctionRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/locations/-/functions"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, functionsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Functions, "gcp cloud function", gcpcloud.SaveRawField[gcpcloud.CloudFunctionRecord])
	return records, response.NextPageToken, err
}

func listVPCAccessConnectors(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.VPCAccessConnectorRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response vpcAccessPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/connectors"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, vpcAccessBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Connectors, "gcp serverless vpc access connector", gcpcloud.SaveRawField[gcpcloud.VPCAccessConnectorRecord])
	return records, response.NextPageToken, err
}

func listCloudSchedulerJobs(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSchedulerJobRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response gcpcloud.CloudSchedulerJobsResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/jobs"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, cloudSchedulerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Jobs, "gcp cloud scheduler job", gcpcloud.SaveRawField[gcpcloud.CloudSchedulerJobRecord])
	return records, response.NextPageToken, err
}

func listContainerVulnerabilities(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ContainerVulnerabilityRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	} else {
		query.Set("filter", `kind="VULNERABILITY"`)
	}
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/occurrences"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, containerAnalysisBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Occurrences, "gcp container vulnerability", gcpcloud.SaveRawField[gcpcloud.ContainerVulnerabilityRecord])
	return records, response.NextPageToken, err
}

func listContainerRegistries(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]gcpcloud.ContainerRegistryRecord, string, error) {
	if strings.TrimSpace(pageToken) != "" {
		return nil, "", nil
	}
	records, err := gcpcloud.ListContainerRegistries(settings.projectID, func(path string, query url.Values, target any) error {
		return getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, path, query, nil, target)
	})
	return records, "", err
}

func listCloudSQLInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSQLInstanceRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/sql/v1beta4/projects/" + url.PathEscape(settings.projectID) + "/instances"
	if err := getJSON(ctx, source, settings, sqlBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Items, "gcp cloud sql instance", gcpcloud.SaveRawField[gcpcloud.CloudSQLInstanceRecord])
	return records, response.NextPageToken, err
}

func listCloudSQLDatabases(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSQLDatabaseRecord, string, error) {
	instances, next, err := listCloudSQLInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectCloudSQLChildRecords(settings.projectID, "databases", "gcp cloud sql database", instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, sqlBaseURL, http.MethodGet, path, query, nil, target))
	}, func(record *gcpcloud.CloudSQLDatabaseRecord, instance gcpcloud.CloudSQLInstanceRecord) {
		record.InstanceName = instance.Name
		record.InstanceRegion = instance.Region
	})
	return records, next, err
}

func listCloudSQLUsers(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSQLUserRecord, string, error) {
	instances, next, err := listCloudSQLInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectCloudSQLChildRecords(settings.projectID, "users", "gcp cloud sql user", instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, sqlBaseURL, http.MethodGet, path, query, nil, target))
	}, func(record *gcpcloud.CloudSQLUserRecord, instance gcpcloud.CloudSQLInstanceRecord) {
		record.InstanceName = instance.Name
		record.InstanceRegion = instance.Region
	})
	return records, next, err
}

func listGCSBuckets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.GCSBucketRecord, string, error) {
	query := url.Values{"project": {settings.projectID}, "maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, "/storage/v1/b", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Items, "gcp storage bucket", gcpcloud.SaveRawField[gcpcloud.GCSBucketRecord])
	return records, response.NextPageToken, err
}

func listGCSObjects(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.GCSObjectRecord, string, error) {
	parentToken, startIndex, childToken, _, err := sourcecdk.DecodeChildPageCursor("gcp", familyGCSObject, pageToken)
	if err != nil {
		return nil, "", err
	}
	buckets, next, err := listGCSBuckets(ctx, source, settings, parentToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.GCSObjectRecord, 0)
	for index := startIndex; index < len(buckets); index++ {
		bucket := buckets[index]
		bucketName := firstNonEmpty(bucket.Name, bucket.ID)
		if strings.TrimSpace(bucketName) == "" {
			childToken = ""
			continue
		}
		path := "/storage/v1/b/" + url.PathEscape(bucketName) + "/o"
		query := url.Values{"maxResults": {strconv.Itoa(limit)}, "projection": {"full"}}
		gcpcloud.AddPageToken(query, childToken)
		if strings.TrimSpace(settings.filter) != "" {
			query.Set("prefix", settings.filter)
		}
		var response pageResponse
		if err := getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
			return nil, "", err
		}
		objects, err := gcpcloud.DecodeRecords(response.Items, "gcp storage object", func(record *gcpcloud.GCSObjectRecord, raw json.RawMessage) {
			if strings.TrimSpace(record.Bucket) == "" {
				record.Bucket = bucketName
			}
			record.BucketLocation = bucket.Location
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		gcpcloud.EnrichGCSObjectContentInspections(objects, func(object gcpcloud.GCSObjectRecord) ([]byte, bool, error) {
			path, query := gcpcloud.GCSObjectContentMediaRequest(object)
			return getBytes(ctx, source, settings, storageBaseURL, http.MethodGet, path, query, nil, gcsObjectContentSampleBytes)
		})
		records = append(records, objects...)
		if response.NextPageToken != "" {
			return records, sourcecdk.EncodeChildPageCursor("gcp", familyGCSObject, parentToken, index, response.NextPageToken), nil
		}
		childToken = ""
		if len(records) != 0 {
			return records, sourcecdk.NextChildPageCursor("gcp", familyGCSObject, parentToken, next, index+1, len(buckets)), nil
		}
	}
	return records, next, nil
}

func listSecrets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SecretRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/secrets"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, secretManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Secrets, "gcp secret", gcpcloud.SaveRawField[gcpcloud.SecretRecord])
	return records, response.NextPageToken, err
}

func listSecretVersions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SecretVersionRecord, string, error) {
	secrets, next, err := listSecrets(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectSecretVersions(secrets, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, secretManagerBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}

func listKMSKeys(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.KMSKeyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(settings.location) + "/keyRings/" + url.PathEscape(settings.keyRing) + "/cryptoKeys"
	if err := getJSON(ctx, source, settings, kmsBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.CryptoKeys, "gcp kms key", gcpcloud.SaveRawField[gcpcloud.KMSKeyRecord])
	return records, response.NextPageToken, err
}

func listLoggingSinks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.LoggingSinkRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/sinks"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, loggingBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Sinks, "gcp logging project sink", gcpcloud.SaveRawField[gcpcloud.LoggingSinkRecord])
	return records, response.NextPageToken, err
}

func listMonitoringAlertPolicies(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.MonitoringAlertPolicyRecord, string, error) {
	return listPagedRecords[gcpcloud.MonitoringAlertPolicyRecord, gcpcloud.MonitoringPageResponse](ctx, source, settings, pageToken, limit, monitoringBaseURL, "/v3/projects/"+url.PathEscape(settings.projectID)+"/alertPolicies", "pageSize", "gcp monitoring alert policy", func(response gcpcloud.MonitoringPageResponse) []json.RawMessage { return response.AlertPolicies }, true, true, nil)
}

func listMonitoringNotificationChannels(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.MonitoringNotificationChannelRecord, string, error) {
	return listPagedRecords[gcpcloud.MonitoringNotificationChannelRecord, gcpcloud.MonitoringPageResponse](ctx, source, settings, pageToken, limit, monitoringBaseURL, "/v3/projects/"+url.PathEscape(settings.projectID)+"/notificationChannels", "pageSize", "gcp monitoring notification channel", func(response gcpcloud.MonitoringPageResponse) []json.RawMessage { return response.NotificationChannels }, true, true, nil)
}

func listLoggingMetrics(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.LoggingMetricRecord, string, error) {
	return listPagedRecords[gcpcloud.LoggingMetricRecord, gcpcloud.LoggingMetricsPageResponse](ctx, source, settings, pageToken, limit, loggingBaseURL, "/v2/projects/"+url.PathEscape(settings.projectID)+"/metrics", "pageSize", "gcp logging metric", func(response gcpcloud.LoggingMetricsPageResponse) []json.RawMessage { return response.Metrics }, true, false, nil)
}

func listPagedRecords[T any, R gcpcloud.PageTokenResponse](ctx context.Context, source *Source, settings settings, pageToken string, limit int, defaultBaseURL func() string, path string, pageSizeParam string, label string, selectRecords func(R) []json.RawMessage, optional bool, useFilter bool, extraQuery url.Values) ([]T, string, error) {
	options := gcpcloud.PagedRecordsOptions{PageToken: pageToken, Limit: limit, PageSizeParam: pageSizeParam, Label: label, Optional: optional, UseFilter: useFilter, Filter: settings.filter, ExtraQuery: extraQuery}
	return gcpcloud.ListPagedRecords[T, R](options, func(query url.Values, response *R) error {
		return getJSON(ctx, source, settings, defaultBaseURL, http.MethodGet, path, query, nil, response)
	}, selectRecords)
}

func listPubSubTopics(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.PubSubTopicRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pubSubPageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/topics"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, pubSubBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Topics, "gcp pubsub topic", gcpcloud.SaveRawField[gcpcloud.PubSubTopicRecord])
	if err != nil {
		return nil, "", err
	}
	if err := attachPubSubIAMPolicies(ctx, source, settings, records); err != nil {
		return nil, "", err
	}
	return records, response.NextPageToken, nil
}

func listPubSubSubscriptions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.PubSubSubscriptionRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pubSubPageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/subscriptions"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, pubSubBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Subscriptions, "gcp pubsub subscription", gcpcloud.SaveRawField[gcpcloud.PubSubSubscriptionRecord])
	if err != nil {
		return nil, "", err
	}
	if err := attachPubSubSubscriptionIAMPolicies(ctx, source, settings, records); err != nil {
		return nil, "", err
	}
	return records, response.NextPageToken, nil
}

func attachPubSubIAMPolicies(ctx context.Context, source *Source, settings settings, records []gcpcloud.PubSubTopicRecord) error {
	for index := range records {
		policy, err := getPubSubIAMPolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			if gcpcloud.OptionalEnrichmentErr(err) != nil {
				return err
			}
			continue
		}
		records[index].IAMPolicy = policy
	}
	return nil
}

func attachPubSubSubscriptionIAMPolicies(ctx context.Context, source *Source, settings settings, records []gcpcloud.PubSubSubscriptionRecord) error {
	for index := range records {
		policy, err := getPubSubIAMPolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			if gcpcloud.OptionalEnrichmentErr(err) != nil {
				return err
			}
			continue
		}
		records[index].IAMPolicy = policy
	}
	return nil
}

func getPubSubIAMPolicy(ctx context.Context, source *Source, settings settings, resourceName string) (gcpcloud.IAMPolicy, error) {
	var policy gcpcloud.IAMPolicy
	path := "/v1/" + gcpcloud.EscapePathSegments(resourceName) + ":getIamPolicy"
	if err := getJSON(ctx, source, settings, pubSubBaseURL, http.MethodPost, path, nil, map[string]any{"options": map[string]int{"requestedPolicyVersion": 3}}, &policy); err != nil {
		return gcpcloud.IAMPolicy{}, err
	}
	return policy, nil
}

func listResourceManagerProjects(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]gcpcloud.ResourceManagerProjectRecord, string, error) {
	var raw json.RawMessage
	path := "/v1/projects/" + url.PathEscape(settings.projectID)
	if err := getJSON(ctx, source, settings, resourceManagerBaseURL, http.MethodGet, path, nil, nil, &raw); err != nil {
		return nil, "", err
	}
	var record gcpcloud.ResourceManagerProjectRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, "", fmt.Errorf("decode gcp resource manager project: %w", err)
	}
	record.Raw = append(json.RawMessage(nil), raw...)
	serviceSettings := settings
	serviceSettings.projectID = firstNonEmpty(record.ProjectNumber, record.ProjectID, settings.projectID)
	services, err := gcpcloud.CollectPages(func(pageToken string) ([]gcpcloud.ServiceUsageServiceRecord, string, error) {
		return listServiceUsageServices(ctx, source, serviceSettings, pageToken, settings.perPage)
	})
	if err != nil && gcpcloud.OptionalEnrichmentErr(err) != nil {
		return nil, "", err
	}
	record.EnabledServices = services
	policies, err := gcpcloud.CollectPages(func(pageToken string) ([]gcpcloud.OrgPolicyRecord, string, error) {
		return listOrgPolicies(ctx, source, settings, pageToken, settings.perPage)
	})
	if err != nil && gcpcloud.OptionalEnrichmentErr(err) != nil {
		return nil, "", err
	}
	record.OrgPolicies = policies
	return []gcpcloud.ResourceManagerProjectRecord{record}, "", nil
}

func listServiceUsageServices(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ServiceUsageServiceRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}, "filter": {"state:ENABLED"}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/services"
	if err := getJSON(ctx, source, settings, serviceUsageBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Services, "gcp service usage service", gcpcloud.SaveRawField[gcpcloud.ServiceUsageServiceRecord])
	return records, response.NextPageToken, err
}

func listOrgPolicies(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.OrgPolicyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/policies"
	if err := getJSON(ctx, source, settings, orgPolicyBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Policies, "gcp organization policy", gcpcloud.SaveRawField[gcpcloud.OrgPolicyRecord])
	return records, response.NextPageToken, err
}

func listArtifactRepositories(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ArtifactRepositoryRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/-/repositories"
	if err := getJSON(ctx, source, settings, artifactRegistryBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Repositories, "gcp artifact registry repository", gcpcloud.SaveRawField[gcpcloud.ArtifactRepositoryRecord])
	return records, response.NextPageToken, err
}

func listArtifactImages(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ArtifactImageRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/" + gcpcloud.EscapePathSegments(settings.artifactRepository) + "/dockerImages"
	if err := getJSON(ctx, source, settings, artifactRegistryBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.DockerImages, "gcp artifact registry image", gcpcloud.SaveRawField[gcpcloud.ArtifactImageRecord])
	return records, response.NextPageToken, err
}

func listResourceExposures(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]firewallRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/global/firewalls"
	if err := getComputeJSON(ctx, source, settings, path, query, &response); err != nil {
		return nil, "", err
	}
	firewalls, err := gcpcloud.DecodeRecords(response.Items, "gcp firewall", func(record *firewallRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	if err != nil {
		return nil, "", err
	}
	exposed := make([]firewallRecord, 0, len(firewalls))
	for _, firewall := range firewalls {
		if firewallPublicIngress(firewall) {
			exposed = append(exposed, firewall)
		}
	}
	return exposed, response.NextPageToken, nil
}

func listAuditRecords(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]auditRecord, string, error) {
	return listAuditRecordsWithCheckpoint(ctx, source, settings, pageToken, limit, nil)
}

func listAuditRecordsWithCheckpoint(ctx context.Context, source *Source, settings settings, pageToken string, limit int, checkpoint *cerebrov1.SourceCheckpoint) ([]auditRecord, string, error) {
	body := map[string]any{"resourceNames": []string{"projects/" + settings.projectID}, "pageSize": limit}
	if start, ok := gcpcloud.CheckpointStart(checkpoint, gcpcloud.FindingCheckpointLookback); ok {
		settings.filter = gcpcloud.CombineFilters(settings.filter, fmt.Sprintf(`timestamp >= "%s"`, start.Format(time.RFC3339Nano)))
		body["orderBy"] = "timestamp desc"
	}
	if settings.filter != "" {
		body["filter"] = settings.filter
	}
	if pageToken != "" {
		body["pageToken"] = pageToken
	}
	var response pageResponse
	if err := getJSON(ctx, source, settings, loggingBaseURL, http.MethodPost, "/v2/entries:list", nil, body, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Entries, "gcp audit log", func(record *auditRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}
