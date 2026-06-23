package gcpcloud

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/primitives"
)

type ComputeInstanceRecord struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Zone              string                    `json:"zone"`
	MachineType       string                    `json:"machineType"`
	Status            string                    `json:"status"`
	Labels            map[string]string         `json:"labels"`
	Tags              ComputeTags               `json:"tags"`
	NetworkInterfaces []ComputeNetworkInterface `json:"networkInterfaces"`
	ServiceAccounts   []ComputeServiceAccount   `json:"serviceAccounts"`
	Disks             []ComputeAttachedDisk     `json:"disks"`
	Raw               json.RawMessage           `json:"-"`
}

type ComputeTags struct {
	Items []string `json:"items"`
}

type ComputeNetworkInterface struct {
	Network       string                `json:"network"`
	Subnetwork    string                `json:"subnetwork"`
	NetworkIP     string                `json:"networkIP"`
	AccessConfigs []ComputeAccessConfig `json:"accessConfigs"`
}

type ComputeAccessConfig struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	NatIP string `json:"natIP"`
}

type ComputeServiceAccount struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

type ComputeAttachedDisk struct {
	Boot              bool                     `json:"boot"`
	AutoDelete        bool                     `json:"autoDelete"`
	Source            string                   `json:"source"`
	DiskEncryptionKey ComputeDiskEncryptionKey `json:"diskEncryptionKey"`
}

type ComputeAddressRecord struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	SelfLink         string            `json:"selfLink"`
	Description      string            `json:"description"`
	Address          string            `json:"address"`
	PrefixLength     int               `json:"prefixLength"`
	Status           string            `json:"status"`
	Region           string            `json:"region"`
	Users            []string          `json:"users"`
	NetworkTier      string            `json:"networkTier"`
	IPVersion        string            `json:"ipVersion"`
	AddressType      string            `json:"addressType"`
	Purpose          string            `json:"purpose"`
	Subnetwork       string            `json:"subnetwork"`
	Network          string            `json:"network"`
	IPv6EndpointType string            `json:"ipv6EndpointType"`
	IPCollection     string            `json:"ipCollection"`
	Labels           map[string]string `json:"labels"`
	Raw              json.RawMessage   `json:"-"`
}

type ComputeBackendBucketRecord struct {
	ID                    string                          `json:"id"`
	Name                  string                          `json:"name"`
	SelfLink              string                          `json:"selfLink"`
	Description           string                          `json:"description"`
	BucketName            string                          `json:"bucketName"`
	EnableCDN             bool                            `json:"enableCdn"`
	CDNPolicy             ComputeBackendBucketCDNPolicy   `json:"cdnPolicy"`
	CustomResponseHeaders []string                        `json:"customResponseHeaders"`
	EdgeSecurityPolicy    string                          `json:"edgeSecurityPolicy"`
	CompressionMode       string                          `json:"compressionMode"`
	LoadBalancingScheme   string                          `json:"loadBalancingScheme"`
	Region                string                          `json:"region"`
	UsedBy                []ComputeBackendBucketReference `json:"usedBy"`
	Raw                   json.RawMessage                 `json:"-"`
}

type ComputeBackendBucketCDNPolicy struct {
	SignedURLKeyNames     []string                                   `json:"signedUrlKeyNames"`
	SignedURLCacheMaxAge  string                                     `json:"signedUrlCacheMaxAgeSec"`
	RequestCoalescing     bool                                       `json:"requestCoalescing"`
	CacheMode             string                                     `json:"cacheMode"`
	DefaultTTL            int                                        `json:"defaultTtl"`
	MaxTTL                int                                        `json:"maxTtl"`
	ClientTTL             int                                        `json:"clientTtl"`
	NegativeCaching       bool                                       `json:"negativeCaching"`
	NegativeCachingPolicy []ComputeBackendBucketNegativeCachingEntry `json:"negativeCachingPolicy"`
	ServeWhileStale       int                                        `json:"serveWhileStale"`
	BypassCacheOnHeaders  []ComputeBackendBucketRequestHeader        `json:"bypassCacheOnRequestHeaders"`
	CacheKeyPolicy        ComputeBackendBucketCacheKeyPolicy         `json:"cacheKeyPolicy"`
}

type ComputeBackendBucketNegativeCachingEntry struct {
	Code int `json:"code"`
	TTL  int `json:"ttl"`
}

type ComputeBackendBucketRequestHeader struct {
	HeaderName string `json:"headerName"`
}

type ComputeBackendBucketCacheKeyPolicy struct {
	QueryStringWhitelist []string `json:"queryStringWhitelist"`
	IncludeHTTPHeaders   []string `json:"includeHttpHeaders"`
}

type ComputeBackendBucketReference struct {
	Reference string `json:"reference"`
}

type ComputeBackendServiceRecord struct {
	ID                   string                                  `json:"id"`
	Name                 string                                  `json:"name"`
	SelfLink             string                                  `json:"selfLink"`
	Description          string                                  `json:"description"`
	Region               string                                  `json:"region"`
	Protocol             string                                  `json:"protocol"`
	PortName             string                                  `json:"portName"`
	LoadBalancingScheme  string                                  `json:"loadBalancingScheme"`
	SessionAffinity      string                                  `json:"sessionAffinity"`
	LocalityLBPolicy     string                                  `json:"localityLbPolicy"`
	TimeoutSec           int                                     `json:"timeoutSec"`
	EnableCDN            bool                                    `json:"enableCDN"`
	HealthChecks         []string                                `json:"healthChecks"`
	Backends             []ComputeBackendServiceBackend          `json:"backends"`
	ConnectionDraining   ComputeBackendServiceConnectionDraining `json:"connectionDraining"`
	LogConfig            ComputeBackendServiceLogConfig          `json:"logConfig"`
	IAP                  ComputeBackendServiceIAP                `json:"iap"`
	SecurityPolicy       string                                  `json:"securityPolicy"`
	Network              string                                  `json:"network"`
	CustomRequestHeaders []string                                `json:"customRequestHeaders"`
	Labels               map[string]string                       `json:"labels"`
	Raw                  json.RawMessage                         `json:"-"`
}

type ComputeBackendServiceBackend struct {
	Group                     string  `json:"group"`
	BalancingMode             string  `json:"balancingMode"`
	CapacityScaler            float64 `json:"capacityScaler"`
	MaxUtilization            float64 `json:"maxUtilization"`
	MaxRatePerInstance        float64 `json:"maxRatePerInstance"`
	MaxConnectionsPerInstance int     `json:"maxConnectionsPerInstance"`
	Failover                  bool    `json:"failover"`
}

type ComputeBackendServiceConnectionDraining struct {
	DrainingTimeoutSec int `json:"drainingTimeoutSec"`
}

type ComputeBackendServiceLogConfig struct {
	Enable     bool    `json:"enable"`
	SampleRate float64 `json:"sampleRate"`
}

type ComputeBackendServiceIAP struct {
	Enabled bool `json:"enabled"`
}

type ComputeNamedPort struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type ComputeInstanceGroupRecord struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	SelfLink    string             `json:"selfLink"`
	Description string             `json:"description"`
	Zone        string             `json:"zone"`
	Region      string             `json:"region"`
	Network     string             `json:"network"`
	Subnetwork  string             `json:"subnetwork"`
	NamedPorts  []ComputeNamedPort `json:"namedPorts"`
	Size        int                `json:"size"`
	Raw         json.RawMessage    `json:"-"`
}

type ComputeInstanceGroupManagerRecord struct {
	ID                  string                           `json:"id"`
	Name                string                           `json:"name"`
	SelfLink            string                           `json:"selfLink"`
	Description         string                           `json:"description"`
	Zone                string                           `json:"zone"`
	Region              string                           `json:"region"`
	BaseInstanceName    string                           `json:"baseInstanceName"`
	InstanceTemplate    string                           `json:"instanceTemplate"`
	TargetSize          int                              `json:"targetSize"`
	TargetPools         []string                         `json:"targetPools"`
	NamedPorts          []ComputeNamedPort               `json:"namedPorts"`
	AutoHealingPolicies []ComputeAutoHealingPolicy       `json:"autoHealingPolicies"`
	CurrentActions      ComputeInstanceGroupActions      `json:"currentActions"`
	Status              ComputeInstanceGroupStatus       `json:"status"`
	UpdatePolicy        ComputeInstanceGroupUpdatePolicy `json:"updatePolicy"`
	DistributionPolicy  ComputeInstanceDistribution      `json:"distributionPolicy"`
	Raw                 json.RawMessage                  `json:"-"`
}

type ComputeAutoHealingPolicy struct {
	HealthCheck     string `json:"healthCheck"`
	InitialDelaySec int    `json:"initialDelaySec"`
}

type ComputeInstanceGroupActions struct {
	None                   int `json:"none"`
	Creating               int `json:"creating"`
	Deleting               int `json:"deleting"`
	Recreating             int `json:"recreating"`
	Refreshing             int `json:"refreshing"`
	Restarting             int `json:"restarting"`
	Verifying              int `json:"verifying"`
	Abandoning             int `json:"abandoning"`
	CreatingWithoutRetries int `json:"creatingWithoutRetries"`
}

type ComputeInstanceGroupStatus struct {
	IsStable      bool `json:"isStable"`
	VersionTarget struct {
		IsReached bool `json:"isReached"`
	} `json:"versionTarget"`
	Stateful struct {
		HasStatefulConfig  bool `json:"hasStatefulConfig"`
		PerInstanceConfigs struct {
			AllEffective bool `json:"allEffective"`
		} `json:"perInstanceConfigs"`
	} `json:"stateful"`
}

type ComputeInstanceGroupUpdatePolicy struct {
	Type                        string `json:"type"`
	MinimalAction               string `json:"minimalAction"`
	MostDisruptiveAllowedAction string `json:"mostDisruptiveAllowedAction"`
	ReplacementMethod           string `json:"replacementMethod"`
	MaxSurge                    string `json:"maxSurge"`
	MaxUnavailable              string `json:"maxUnavailable"`
}

type ComputeInstanceDistribution struct {
	Zones []ComputeInstanceDistributionZone `json:"zones"`
}

type ComputeInstanceDistributionZone struct {
	Zone string `json:"zone"`
}

type ComputeInstanceTemplateRecord struct {
	ID          string                            `json:"id"`
	Name        string                            `json:"name"`
	SelfLink    string                            `json:"selfLink"`
	Description string                            `json:"description"`
	Properties  ComputeInstanceTemplateProperties `json:"properties"`
	Raw         json.RawMessage                   `json:"-"`
}

type ComputeInstanceTemplateProperties struct {
	MachineType            string                    `json:"machineType"`
	Labels                 map[string]string         `json:"labels"`
	Tags                   ComputeTags               `json:"tags"`
	NetworkInterfaces      []ComputeNetworkInterface `json:"networkInterfaces"`
	ServiceAccounts        []ComputeServiceAccount   `json:"serviceAccounts"`
	Disks                  []ComputeAttachedDisk     `json:"disks"`
	ShieldedInstanceConfig ComputeShieldedInstance   `json:"shieldedInstanceConfig"`
}

type ComputeShieldedInstance struct {
	EnableSecureBoot          bool `json:"enableSecureBoot"`
	EnableVtpm                bool `json:"enableVtpm"`
	EnableIntegrityMonitoring bool `json:"enableIntegrityMonitoring"`
}

type ComputeNetworkEndpointGroupRecord struct {
	ID                  string                  `json:"id"`
	Name                string                  `json:"name"`
	SelfLink            string                  `json:"selfLink"`
	Description         string                  `json:"description"`
	Zone                string                  `json:"zone"`
	Region              string                  `json:"region"`
	Network             string                  `json:"network"`
	Subnetwork          string                  `json:"subnetwork"`
	NetworkEndpointType string                  `json:"networkEndpointType"`
	DefaultPort         int                     `json:"defaultPort"`
	Size                int                     `json:"size"`
	PscTargetService    string                  `json:"pscTargetService"`
	CloudRun            ComputeNEGCloudRun      `json:"cloudRun"`
	CloudFunction       ComputeNEGCloudFunction `json:"cloudFunction"`
	AppEngine           ComputeNEGAppEngine     `json:"appEngine"`
	Annotations         map[string]string       `json:"annotations"`
	Raw                 json.RawMessage         `json:"-"`
}

type ComputeNEGCloudRun struct {
	Service string `json:"service"`
	Tag     string `json:"tag"`
	URLMask string `json:"urlMask"`
}

type ComputeNEGCloudFunction struct {
	Function string `json:"function"`
	URLMask  string `json:"urlMask"`
}

type ComputeNEGAppEngine struct {
	Service string `json:"service"`
	Version string `json:"version"`
	URLMask string `json:"urlMask"`
}

type ComputeRouterRecord struct {
	ID                          string                 `json:"id"`
	Name                        string                 `json:"name"`
	SelfLink                    string                 `json:"selfLink"`
	Description                 string                 `json:"description"`
	Region                      string                 `json:"region"`
	Network                     string                 `json:"network"`
	NCCGateway                  string                 `json:"nccGateway"`
	Interfaces                  []ComputeRouterIface   `json:"interfaces"`
	BGPPeers                    []ComputeRouterBGPPeer `json:"bgpPeers"`
	BGP                         ComputeRouterBGP       `json:"bgp"`
	NATs                        []ComputeRouterNAT     `json:"nats"`
	EncryptedInterconnectRouter bool                   `json:"encryptedInterconnectRouter"`
	Raw                         json.RawMessage        `json:"-"`
}

type ComputeRouterIface struct {
	Name                         string `json:"name"`
	IPRange                      string `json:"ipRange"`
	PrivateIPAddress             string `json:"privateIpAddress"`
	Subnetwork                   string `json:"subnetwork"`
	LinkedVPNTunnel              string `json:"linkedVpnTunnel"`
	LinkedInterconnectAttachment string `json:"linkedInterconnectAttachment"`
	ManagementType               string `json:"managementType"`
}

type ComputeRouterBGPPeer struct {
	Name                       string `json:"name"`
	InterfaceName              string `json:"interfaceName"`
	IPAddress                  string `json:"ipAddress"`
	PeerIPAddress              string `json:"peerIpAddress"`
	PeerASN                    int64  `json:"peerAsn"`
	AdvertiseMode              string `json:"advertiseMode"`
	AdvertisedRoutePriority    int    `json:"advertisedRoutePriority"`
	Enable                     string `json:"enable"`
	EnableIPv4                 bool   `json:"enableIpv4"`
	EnableIPv6                 bool   `json:"enableIpv6"`
	RouterApplianceInstance    string `json:"routerApplianceInstance"`
	ManagementType             string `json:"managementType"`
	MD5AuthenticationKeyName   string `json:"md5AuthenticationKeyName"`
	CustomLearnedRoutePriority int    `json:"customLearnedRoutePriority"`
}

type ComputeRouterBGP struct {
	ASN               int64    `json:"asn"`
	AdvertiseMode     string   `json:"advertiseMode"`
	AdvertisedGroups  []string `json:"advertisedGroups"`
	KeepaliveInterval int      `json:"keepaliveInterval"`
	IdentifierRange   string   `json:"identifierRange"`
}

type ComputeRouterNAT struct {
	Name                          string                       `json:"name"`
	Type                          string                       `json:"type"`
	NATIPAllocateOption           string                       `json:"natIpAllocateOption"`
	SourceSubnetworkIPRangesToNAT string                       `json:"sourceSubnetworkIpRangesToNat"`
	NATIPs                        []string                     `json:"natIps"`
	DrainNATIPs                   []string                     `json:"drainNatIps"`
	MinPortsPerVM                 int                          `json:"minPortsPerVm"`
	MaxPortsPerVM                 int                          `json:"maxPortsPerVm"`
	EnableDynamicPortAllocation   bool                         `json:"enableDynamicPortAllocation"`
	EnableEndpointIndependentMap  bool                         `json:"enableEndpointIndependentMapping"`
	EndpointTypes                 []string                     `json:"endpointTypes"`
	Subnetworks                   []ComputeRouterNATSubnetwork `json:"subnetworks"`
	LogConfig                     ComputeRouterNATLogConfig    `json:"logConfig"`
	Rules                         []ComputeRouterNATRule       `json:"rules"`
}

type ComputeRouterNATSubnetwork struct {
	Name                  string   `json:"name"`
	SourceIPRangesToNAT   []string `json:"sourceIpRangesToNat"`
	SecondaryIPRangeNames []string `json:"secondaryIpRangeNames"`
}

type ComputeRouterNATLogConfig struct {
	Enable bool   `json:"enable"`
	Filter string `json:"filter"`
}

type ComputeRouterNATRule struct {
	RuleNumber int    `json:"ruleNumber"`
	Match      string `json:"match"`
	Action     struct {
		SourceNATActiveIPs []string `json:"sourceNatActiveIps"`
		SourceNATDrainIPs  []string `json:"sourceNatDrainIps"`
	} `json:"action"`
}

type ComputeVPNGatewayRecord struct {
	ID               string                       `json:"id"`
	Name             string                       `json:"name"`
	SelfLink         string                       `json:"selfLink"`
	Description      string                       `json:"description"`
	Region           string                       `json:"region"`
	Network          string                       `json:"network"`
	GatewayIPVersion string                       `json:"gatewayIpVersion"`
	StackType        string                       `json:"stackType"`
	VPNInterfaces    []ComputeVPNGatewayInterface `json:"vpnInterfaces"`
	Labels           map[string]string            `json:"labels"`
	Raw              json.RawMessage              `json:"-"`
}

type ComputeVPNGatewayInterface struct {
	ID        int    `json:"id"`
	IPAddress string `json:"ipAddress"`
}

type ComputeTargetVPNGatewayRecord struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	SelfLink        string            `json:"selfLink"`
	Description     string            `json:"description"`
	Region          string            `json:"region"`
	Network         string            `json:"network"`
	Status          string            `json:"status"`
	Tunnels         []string          `json:"tunnels"`
	ForwardingRules []string          `json:"forwardingRules"`
	Labels          map[string]string `json:"labels"`
	Raw             json.RawMessage   `json:"-"`
}

type ComputeVPNTunnelRecord struct {
	ID                       string            `json:"id"`
	Name                     string            `json:"name"`
	SelfLink                 string            `json:"selfLink"`
	Description              string            `json:"description"`
	Region                   string            `json:"region"`
	Status                   string            `json:"status"`
	DetailedStatus           string            `json:"detailedStatus"`
	IKEVersion               int               `json:"ikeVersion"`
	PeerIP                   string            `json:"peerIp"`
	PeerExternalGateway      string            `json:"peerExternalGateway"`
	PeerExternalGatewayIface int               `json:"peerExternalGatewayInterface"`
	PeerGCPGateway           string            `json:"peerGcpGateway"`
	TargetVPNGateway         string            `json:"targetVpnGateway"`
	VPNGateway               string            `json:"vpnGateway"`
	VPNGatewayInterface      int               `json:"vpnGatewayInterface"`
	Router                   string            `json:"router"`
	LocalTrafficSelector     []string          `json:"localTrafficSelector"`
	RemoteTrafficSelector    []string          `json:"remoteTrafficSelector"`
	SharedSecretHash         string            `json:"sharedSecretHash"`
	Labels                   map[string]string `json:"labels"`
	Raw                      json.RawMessage   `json:"-"`
}

type ComputeInterconnectAttachmentRecord struct {
	ID                      string            `json:"id"`
	Name                    string            `json:"name"`
	SelfLink                string            `json:"selfLink"`
	Description             string            `json:"description"`
	Region                  string            `json:"region"`
	Router                  string            `json:"router"`
	Interconnect            string            `json:"interconnect"`
	Type                    string            `json:"type"`
	AdminEnabled            bool              `json:"adminEnabled"`
	OperationalStatus       string            `json:"operationalStatus"`
	State                   string            `json:"state"`
	Bandwidth               string            `json:"bandwidth"`
	EdgeAvailabilityDomain  string            `json:"edgeAvailabilityDomain"`
	VlanTag8021q            int               `json:"vlanTag8021q"`
	MTU                     int               `json:"mtu"`
	Encryption              string            `json:"encryption"`
	StackType               string            `json:"stackType"`
	CloudRouterIPAddress    string            `json:"cloudRouterIpAddress"`
	CustomerRouterIPAddress string            `json:"customerRouterIpAddress"`
	IPSecInternalAddresses  []string          `json:"ipsecInternalAddresses"`
	SatisfiesPzs            bool              `json:"satisfiesPzs"`
	Labels                  map[string]string `json:"labels"`
	Raw                     json.RawMessage   `json:"-"`
}

type ComputeExternalVPNGatewayRecord struct {
	ID             string                               `json:"id"`
	Name           string                               `json:"name"`
	SelfLink       string                               `json:"selfLink"`
	Description    string                               `json:"description"`
	RedundancyType string                               `json:"redundancyType"`
	Interfaces     []ComputeExternalVPNGatewayInterface `json:"interfaces"`
	Labels         map[string]string                    `json:"labels"`
	Raw            json.RawMessage                      `json:"-"`
}

type ComputeExternalVPNGatewayInterface struct {
	ID          int    `json:"id"`
	IPAddress   string `json:"ipAddress"`
	IPv6Address string `json:"ipv6Address"`
}

type ComputeInterconnectRecord struct {
	ID                      string                      `json:"id"`
	Name                    string                      `json:"name"`
	SelfLink                string                      `json:"selfLink"`
	Description             string                      `json:"description"`
	Location                string                      `json:"location"`
	RemoteLocation          string                      `json:"remoteLocation"`
	LinkType                string                      `json:"linkType"`
	InterconnectType        string                      `json:"interconnectType"`
	RequestedLinkCount      int                         `json:"requestedLinkCount"`
	ProvisionedLinkCount    int                         `json:"provisionedLinkCount"`
	AdminEnabled            bool                        `json:"adminEnabled"`
	OperationalStatus       string                      `json:"operationalStatus"`
	State                   string                      `json:"state"`
	InterconnectAttachments []string                    `json:"interconnectAttachments"`
	PeerIPAddress           string                      `json:"peerIpAddress"`
	GoogleIPAddress         string                      `json:"googleIpAddress"`
	ExpectedOutages         []ComputeInterconnectOutage `json:"expectedOutages"`
	Labels                  map[string]string           `json:"labels"`
	SatisfiesPzs            bool                        `json:"satisfiesPzs"`
	MACsec                  ComputeInterconnectMACsec   `json:"macsec"`
	MACsecEnabled           bool                        `json:"macsecEnabled"`
	RequestedFeatures       []string                    `json:"requestedFeatures"`
	AvailableFeatures       []string                    `json:"availableFeatures"`
	Raw                     json.RawMessage             `json:"-"`
}

type ComputeInterconnectOutage struct {
	Name             string   `json:"name"`
	State            string   `json:"state"`
	IssueType        string   `json:"issueType"`
	AffectedCircuits []string `json:"affectedCircuits"`
}

type ComputeInterconnectMACsec struct {
	FailOpen bool `json:"failOpen"`
}

type ComputePacketMirroringRecord struct {
	ID                string                          `json:"id"`
	Name              string                          `json:"name"`
	SelfLink          string                          `json:"selfLink"`
	Description       string                          `json:"description"`
	Region            string                          `json:"region"`
	Network           ComputePacketMirroringReference `json:"network"`
	Priority          int                             `json:"priority"`
	CollectorILB      ComputePacketMirroringCollector `json:"collectorIlb"`
	MirroredResources ComputePacketMirroringResources `json:"mirroredResources"`
	Filter            ComputePacketMirroringFilter    `json:"filter"`
	Enable            string                          `json:"enable"`
	Raw               json.RawMessage                 `json:"-"`
}

type ComputePacketMirroringCollector struct {
	URL          string `json:"url"`
	CanonicalURL string `json:"canonicalUrl"`
}

type ComputePacketMirroringReference struct {
	URL          string `json:"url"`
	CanonicalURL string `json:"canonicalUrl"`
}

type ComputePacketMirroringResources struct {
	Subnetworks []ComputePacketMirroringReference `json:"subnetworks"`
	Instances   []ComputePacketMirroringReference `json:"instances"`
	Tags        []string                          `json:"tags"`
}

type ComputePacketMirroringFilter struct {
	CIDRRanges  []string `json:"cidrRanges"`
	IPProtocols []string `json:"IPProtocols"`
	Direction   string   `json:"direction"`
}

type ComputeNetworkFirewallPolicyRecord struct {
	ID                   string                             `json:"id"`
	Name                 string                             `json:"name"`
	SelfLink             string                             `json:"selfLink"`
	SelfLinkWithID       string                             `json:"selfLinkWithId"`
	Description          string                             `json:"description"`
	Region               string                             `json:"region"`
	Parent               string                             `json:"parent"`
	PolicyType           string                             `json:"policyType"`
	ShortName            string                             `json:"shortName"`
	DisplayName          string                             `json:"displayName"`
	Rules                []ComputeFirewallPolicyRule        `json:"rules"`
	PacketMirroringRules []ComputeFirewallPolicyRule        `json:"packetMirroringRules"`
	Associations         []ComputeFirewallPolicyAssociation `json:"associations"`
	RuleTupleCount       int                                `json:"ruleTupleCount"`
	Raw                  json.RawMessage                    `json:"-"`
}

type ComputeFirewallPolicyRule struct {
	RuleName              string                           `json:"ruleName"`
	Description           string                           `json:"description"`
	Priority              int                              `json:"priority"`
	Action                string                           `json:"action"`
	Direction             string                           `json:"direction"`
	EnableLogging         bool                             `json:"enableLogging"`
	Disabled              bool                             `json:"disabled"`
	TargetResources       []string                         `json:"targetResources"`
	TargetServiceAccounts []string                         `json:"targetServiceAccounts"`
	TargetForwardingRules []string                         `json:"targetForwardingRules"`
	SecurityProfileGroup  string                           `json:"securityProfileGroup"`
	TLSInspect            bool                             `json:"tlsInspect"`
	TargetType            string                           `json:"targetType"`
	Match                 ComputeFirewallPolicyRuleMatcher `json:"match"`
}

type ComputeFirewallPolicyRuleMatcher struct {
	SrcIPRanges     []string                            `json:"srcIpRanges"`
	DestIPRanges    []string                            `json:"destIpRanges"`
	Layer4Configs   []ComputeFirewallPolicyLayer4Config `json:"layer4Configs"`
	SrcSecureTags   []ComputeFirewallPolicySecureTag    `json:"srcSecureTags"`
	SrcNetworks     []string                            `json:"srcNetworks"`
	SrcNetworkType  string                              `json:"srcNetworkType"`
	DestNetworkType string                              `json:"destNetworkType"`
}

type ComputeFirewallPolicyLayer4Config struct {
	IPProtocol string   `json:"ipProtocol"`
	Ports      []string `json:"ports"`
}

type ComputeFirewallPolicySecureTag struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type ComputeFirewallPolicyAssociation struct {
	Name             string `json:"name"`
	AttachmentTarget string `json:"attachmentTarget"`
	FirewallPolicyID string `json:"firewallPolicyId"`
	ShortName        string `json:"shortName"`
	DisplayName      string `json:"displayName"`
}

type ComputeHealthCheckRecord struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	SelfLink           string                  `json:"selfLink"`
	Description        string                  `json:"description"`
	CheckIntervalSec   int                     `json:"checkIntervalSec"`
	TimeoutSec         int                     `json:"timeoutSec"`
	UnhealthyThreshold int                     `json:"unhealthyThreshold"`
	HealthyThreshold   int                     `json:"healthyThreshold"`
	Type               string                  `json:"type"`
	TCPHealthCheck     ComputeHealthCheckProbe `json:"tcpHealthCheck"`
	SSLHealthCheck     ComputeHealthCheckProbe `json:"sslHealthCheck"`
	HTTPHealthCheck    ComputeHealthCheckProbe `json:"httpHealthCheck"`
	HTTPSHealthCheck   ComputeHealthCheckProbe `json:"httpsHealthCheck"`
	HTTP2HealthCheck   ComputeHealthCheckProbe `json:"http2HealthCheck"`
	GRPCHealthCheck    ComputeHealthCheckProbe `json:"grpcHealthCheck"`
	GRPCTLSHealthCheck ComputeHealthCheckProbe `json:"grpcTlsHealthCheck"`
	SourceRegions      []string                `json:"sourceRegions"`
	Region             string                  `json:"region"`
	LogConfig          ComputeHealthCheckLog   `json:"logConfig"`
	Raw                json.RawMessage         `json:"-"`
}

type ComputeHealthCheckProbe struct {
	Port              int    `json:"port"`
	PortName          string `json:"portName"`
	PortSpecification string `json:"portSpecification"`
	Request           string `json:"request"`
	Response          string `json:"response"`
	ProxyHeader       string `json:"proxyHeader"`
	Host              string `json:"host"`
	RequestPath       string `json:"requestPath"`
	GRPCServiceName   string `json:"grpcServiceName"`
}

type ComputeHealthCheckLog struct {
	Enable bool `json:"enable"`
}

type ComputeSecurityPolicyRecord struct {
	ID                       string                                  `json:"id"`
	Name                     string                                  `json:"name"`
	SelfLink                 string                                  `json:"selfLink"`
	Description              string                                  `json:"description"`
	Region                   string                                  `json:"region"`
	Type                     string                                  `json:"type"`
	Fingerprint              string                                  `json:"fingerprint"`
	Rules                    []ComputeSecurityPolicyRule             `json:"rules"`
	AdaptiveProtectionConfig ComputeSecurityPolicyAdaptiveProtection `json:"adaptiveProtectionConfig"`
	AdvancedOptionsConfig    ComputeSecurityPolicyAdvancedOptions    `json:"advancedOptionsConfig"`
	Associations             []ComputeSecurityPolicyAssociation      `json:"associations"`
	Labels                   map[string]string                       `json:"labels"`
	Raw                      json.RawMessage                         `json:"-"`
}

type ComputeSecurityPolicyRule struct {
	Priority    int                        `json:"priority"`
	Description string                     `json:"description"`
	Action      string                     `json:"action"`
	Preview     bool                       `json:"preview"`
	Match       ComputeSecurityPolicyMatch `json:"match"`
}

type ComputeSecurityPolicyMatch struct {
	VersionedExpr string                           `json:"versionedExpr"`
	Config        ComputeSecurityPolicyMatchConfig `json:"config"`
	Expr          ComputeSecurityPolicyExpr        `json:"expr"`
}

type ComputeSecurityPolicyMatchConfig struct {
	SrcIPRanges []string `json:"srcIpRanges"`
}

type ComputeSecurityPolicyExpr struct {
	Expression string `json:"expression"`
}

type ComputeSecurityPolicyAdaptiveProtection struct {
	Layer7DDoSDefenseConfig ComputeSecurityPolicyLayer7DDoSDefense `json:"layer7DdosDefenseConfig"`
}

type ComputeSecurityPolicyLayer7DDoSDefense struct {
	Enable bool `json:"enable"`
}

type ComputeSecurityPolicyAdvancedOptions struct {
	JSONParsing          string   `json:"jsonParsing"`
	LogLevel             string   `json:"logLevel"`
	UserIPRequestHeaders []string `json:"userIpRequestHeaders"`
}

type ComputeSecurityPolicyAssociation struct {
	Name             string   `json:"name"`
	AttachmentID     string   `json:"attachmentId"`
	ExcludedProjects []string `json:"excludedProjects"`
	ExcludedFolders  []string `json:"excludedFolders"`
	SecurityPolicyID string   `json:"securityPolicyId"`
	ShortName        string   `json:"shortName"`
}

type ComputeURLMapRecord struct {
	ID                 string                     `json:"id"`
	Name               string                     `json:"name"`
	SelfLink           string                     `json:"selfLink"`
	Description        string                     `json:"description"`
	Region             string                     `json:"region"`
	DefaultService     string                     `json:"defaultService"`
	DefaultRouteAction ComputeURLMapRouteAction   `json:"defaultRouteAction"`
	DefaultURLRedirect ComputeURLMapURLRedirect   `json:"defaultUrlRedirect"`
	HostRules          []ComputeURLMapHostRule    `json:"hostRules"`
	PathMatchers       []ComputeURLMapPathMatcher `json:"pathMatchers"`
	Tests              []ComputeURLMapTest        `json:"tests"`
	Fingerprint        string                     `json:"fingerprint"`
	Raw                json.RawMessage            `json:"-"`
}

type ComputeURLMapHostRule struct {
	Description string   `json:"description"`
	Hosts       []string `json:"hosts"`
	PathMatcher string   `json:"pathMatcher"`
}

type ComputeURLMapPathMatcher struct {
	Name               string                   `json:"name"`
	Description        string                   `json:"description"`
	DefaultService     string                   `json:"defaultService"`
	DefaultRouteAction ComputeURLMapRouteAction `json:"defaultRouteAction"`
	DefaultURLRedirect ComputeURLMapURLRedirect `json:"defaultUrlRedirect"`
	PathRules          []ComputeURLMapPathRule  `json:"pathRules"`
	RouteRules         []ComputeURLMapRouteRule `json:"routeRules"`
}

type ComputeURLMapPathRule struct {
	Paths       []string                 `json:"paths"`
	Service     string                   `json:"service"`
	RouteAction ComputeURLMapRouteAction `json:"routeAction"`
	URLRedirect ComputeURLMapURLRedirect `json:"urlRedirect"`
}

type ComputeURLMapRouteRule struct {
	Priority    int                      `json:"priority"`
	Service     string                   `json:"service"`
	RouteAction ComputeURLMapRouteAction `json:"routeAction"`
	URLRedirect ComputeURLMapURLRedirect `json:"urlRedirect"`
}

type ComputeURLMapRouteAction struct {
	WeightedBackendServices []ComputeURLMapWeightedBackendService `json:"weightedBackendServices"`
}

type ComputeURLMapWeightedBackendService struct {
	BackendService string `json:"backendService"`
	Weight         int    `json:"weight"`
}

type ComputeURLMapURLRedirect struct {
	HostRedirect         string `json:"hostRedirect"`
	PathRedirect         string `json:"pathRedirect"`
	PrefixRedirect       string `json:"prefixRedirect"`
	RedirectResponseCode string `json:"redirectResponseCode"`
	HTTPSRedirect        bool   `json:"httpsRedirect"`
	StripQuery           bool   `json:"stripQuery"`
}

type ComputeURLMapTest struct {
	Description string `json:"description"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Service     string `json:"service"`
}

type ComputeTargetHTTPProxyRecord struct {
	ID                      string          `json:"id"`
	Name                    string          `json:"name"`
	SelfLink                string          `json:"selfLink"`
	Description             string          `json:"description"`
	URLMap                  string          `json:"urlMap"`
	Region                  string          `json:"region"`
	ProxyBind               bool            `json:"proxyBind"`
	Fingerprint             string          `json:"fingerprint"`
	HTTPKeepAliveTimeoutSec int             `json:"httpKeepAliveTimeoutSec"`
	Raw                     json.RawMessage `json:"-"`
}

type ComputeTargetHTTPSProxyRecord struct {
	ID                      string          `json:"id"`
	Name                    string          `json:"name"`
	SelfLink                string          `json:"selfLink"`
	Description             string          `json:"description"`
	URLMap                  string          `json:"urlMap"`
	SSLCertificates         []string        `json:"sslCertificates"`
	CertificateMap          string          `json:"certificateMap"`
	QUICOverride            string          `json:"quicOverride"`
	SSLPolicy               string          `json:"sslPolicy"`
	Region                  string          `json:"region"`
	ProxyBind               bool            `json:"proxyBind"`
	ServerTLSPolicy         string          `json:"serverTlsPolicy"`
	AuthorizationPolicy     string          `json:"authorizationPolicy"`
	Fingerprint             string          `json:"fingerprint"`
	HTTPKeepAliveTimeoutSec int             `json:"httpKeepAliveTimeoutSec"`
	Raw                     json.RawMessage `json:"-"`
}

type ComputeTargetSSLProxyRecord struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	SelfLink        string          `json:"selfLink"`
	Description     string          `json:"description"`
	Service         string          `json:"service"`
	SSLCertificates []string        `json:"sslCertificates"`
	CertificateMap  string          `json:"certificateMap"`
	SSLPolicy       string          `json:"sslPolicy"`
	ProxyHeader     string          `json:"proxyHeader"`
	Raw             json.RawMessage `json:"-"`
}

type ComputeTargetTCPProxyRecord struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	SelfLink            string          `json:"selfLink"`
	Description         string          `json:"description"`
	Service             string          `json:"service"`
	ProxyHeader         string          `json:"proxyHeader"`
	ProxyBind           bool            `json:"proxyBind"`
	LoadBalancingScheme string          `json:"loadBalancingScheme"`
	Region              string          `json:"region"`
	Raw                 json.RawMessage `json:"-"`
}

type ComputeTargetGRPCProxyRecord struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	SelfLink             string          `json:"selfLink"`
	Description          string          `json:"description"`
	URLMap               string          `json:"urlMap"`
	ValidateForProxyless bool            `json:"validateForProxyless"`
	Fingerprint          string          `json:"fingerprint"`
	Raw                  json.RawMessage `json:"-"`
}

type ComputeSSLPolicyRecord struct {
	ID                     string          `json:"id"`
	Name                   string          `json:"name"`
	SelfLink               string          `json:"selfLink"`
	Description            string          `json:"description"`
	Profile                string          `json:"profile"`
	MinTLSVersion          string          `json:"minTlsVersion"`
	EnabledFeatures        []string        `json:"enabledFeatures"`
	CustomFeatures         []string        `json:"customFeatures"`
	PostQuantumKeyExchange string          `json:"postQuantumKeyExchange"`
	Fingerprint            string          `json:"fingerprint"`
	Region                 string          `json:"region"`
	Raw                    json.RawMessage `json:"-"`
}

type ComputeSSLCertificateRecord struct {
	ID                      string                           `json:"id"`
	Name                    string                           `json:"name"`
	SelfLink                string                           `json:"selfLink"`
	Description             string                           `json:"description"`
	Managed                 ComputeSSLCertificateManaged     `json:"managed"`
	SelfManaged             ComputeSSLCertificateSelfManaged `json:"selfManaged"`
	Type                    string                           `json:"type"`
	SubjectAlternativeNames []string                         `json:"subjectAlternativeNames"`
	ExpireTime              string                           `json:"expireTime"`
	Region                  string                           `json:"region"`
	Raw                     json.RawMessage                  `json:"-"`
}

type ComputeSSLCertificateManaged struct {
	Domains      []string          `json:"domains"`
	Status       string            `json:"status"`
	DomainStatus map[string]string `json:"domainStatus"`
}

type ComputeSSLCertificateSelfManaged struct {
	Certificate string `json:"certificate"`
}

type ComputeNetworkRecord struct {
	ID                    string                      `json:"id"`
	Name                  string                      `json:"name"`
	SelfLink              string                      `json:"selfLink"`
	Description           string                      `json:"description"`
	AutoCreateSubnetworks bool                        `json:"autoCreateSubnetworks"`
	RoutingConfig         ComputeNetworkRoutingConfig `json:"routingConfig"`
	Labels                map[string]string           `json:"labels"`
	Raw                   json.RawMessage             `json:"-"`
}

type ComputeNetworkRoutingConfig struct {
	RoutingMode string `json:"routingMode"`
}

type ComputeFirewallRecord struct {
	ID                    string                   `json:"id"`
	Name                  string                   `json:"name"`
	Network               string                   `json:"network"`
	Direction             string                   `json:"direction"`
	Disabled              bool                     `json:"disabled"`
	SourceRanges          []string                 `json:"sourceRanges"`
	Allowed               []ComputeFirewallAllowed `json:"allowed"`
	TargetTags            []string                 `json:"targetTags"`
	TargetServiceAccounts []string                 `json:"targetServiceAccounts"`
	Raw                   json.RawMessage          `json:"-"`
}

type ComputeFirewallAllowed struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports"`
}

type ComputeRouteRecord struct {
	ID                            string          `json:"id"`
	Name                          string          `json:"name"`
	SelfLink                      string          `json:"selfLink"`
	Description                   string          `json:"description"`
	Network                       string          `json:"network"`
	DestRange                     string          `json:"destRange"`
	Priority                      int             `json:"priority"`
	Tags                          []string        `json:"tags"`
	NextHopGateway                string          `json:"nextHopGateway"`
	NextHopInstance               string          `json:"nextHopInstance"`
	NextHopIP                     string          `json:"nextHopIp"`
	NextHopVPNGateway             string          `json:"nextHopVpnGateway"`
	NextHopVPNTunnel              string          `json:"nextHopVpnTunnel"`
	NextHopILB                    string          `json:"nextHopIlb"`
	NextHopNetwork                string          `json:"nextHopNetwork"`
	NextHopPeering                string          `json:"nextHopPeering"`
	NextHopHub                    string          `json:"nextHopHub"`
	NextHopInterconnectAttachment string          `json:"nextHopInterconnectAttachment"`
	RouteType                     string          `json:"routeType"`
	RouteStatus                   string          `json:"routeStatus"`
	NextHopOrigin                 string          `json:"nextHopOrigin"`
	NextHopMed                    int             `json:"nextHopMed"`
	CreationTimestamp             string          `json:"creationTimestamp"`
	Raw                           json.RawMessage `json:"-"`
}

type ComputeForwardingRuleRecord struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	SelfLink            string            `json:"selfLink"`
	Description         string            `json:"description"`
	Region              string            `json:"region"`
	IPAddress           string            `json:"IPAddress"`
	IPProtocol          string            `json:"IPProtocol"`
	IPVersion           string            `json:"ipVersion"`
	LoadBalancingScheme string            `json:"loadBalancingScheme"`
	PortRange           string            `json:"portRange"`
	Ports               []string          `json:"ports"`
	AllPorts            bool              `json:"allPorts"`
	AllowGlobalAccess   bool              `json:"allowGlobalAccess"`
	Network             string            `json:"network"`
	Subnetwork          string            `json:"subnetwork"`
	NetworkTier         string            `json:"networkTier"`
	Target              string            `json:"target"`
	BackendService      string            `json:"backendService"`
	ServiceLabel        string            `json:"serviceLabel"`
	ServiceName         string            `json:"serviceName"`
	Labels              map[string]string `json:"labels"`
	Raw                 json.RawMessage   `json:"-"`
}

type ComputeSubnetworkRecord struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	SelfLink              string            `json:"selfLink"`
	Network               string            `json:"network"`
	Region                string            `json:"region"`
	IPCIDRRange           string            `json:"ipCidrRange"`
	PrivateIPGoogleAccess bool              `json:"privateIpGoogleAccess"`
	Purpose               string            `json:"purpose"`
	Role                  string            `json:"role"`
	StackType             string            `json:"stackType"`
	Labels                map[string]string `json:"labels"`
	Raw                   json.RawMessage   `json:"-"`
}

type ComputeDiskRecord struct {
	ID                string                   `json:"id"`
	Name              string                   `json:"name"`
	SelfLink          string                   `json:"selfLink"`
	Zone              string                   `json:"zone"`
	Region            string                   `json:"region"`
	Type              string                   `json:"type"`
	Status            string                   `json:"status"`
	SizeGB            string                   `json:"sizeGb"`
	Users             []string                 `json:"users"`
	Labels            map[string]string        `json:"labels"`
	DiskEncryptionKey ComputeDiskEncryptionKey `json:"diskEncryptionKey"`
	Raw               json.RawMessage          `json:"-"`
}

type ComputeDiskEncryptionKey struct {
	KMSKeyName string `json:"kmsKeyName"`
}

type VPCAccessConnectorRecord struct {
	Name              string                   `json:"name"`
	Network           string                   `json:"network"`
	IPCIDRRange       string                   `json:"ipCidrRange"`
	State             string                   `json:"state"`
	MinThroughput     int                      `json:"minThroughput"`
	MaxThroughput     int                      `json:"maxThroughput"`
	ConnectedProjects []string                 `json:"connectedProjects"`
	Subnet            VPCAccessConnectorSubnet `json:"subnet"`
	MachineType       string                   `json:"machineType"`
	MinInstances      int                      `json:"minInstances"`
	MaxInstances      int                      `json:"maxInstances"`
	Raw               json.RawMessage          `json:"-"`
}

type VPCAccessConnectorSubnet struct {
	Name      string `json:"name"`
	ProjectID string `json:"projectId"`
}

func (record ComputeAddressRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name, record.Address)
}

func (record ComputeBackendBucketRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name, record.BucketName)
}

func (record ComputeBackendServiceRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInstanceGroupRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInstanceGroupManagerRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInstanceTemplateRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeNetworkEndpointGroupRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeRouterRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeVPNGatewayRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetVPNGatewayRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeVPNTunnelRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInterconnectAttachmentRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeExternalVPNGatewayRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInterconnectRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputePacketMirroringRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeNetworkFirewallPolicyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.SelfLinkWithID, record.ID, record.Name)
}

func (record ComputeDiskRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeForwardingRuleRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeHealthCheckRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeNetworkRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeRouteRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSecurityPolicyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSSLCertificateRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSubnetworkRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetHTTPProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetHTTPSProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetSSLProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetTCPProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetGRPCProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSSLPolicyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeURLMapRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record VPCAccessConnectorRecord) CerebroResourceID() string {
	return record.Name
}

type GKEClusterRecord struct {
	Name                           string                            `json:"name"`
	SelfLink                       string                            `json:"selfLink"`
	Location                       string                            `json:"location"`
	Endpoint                       string                            `json:"endpoint"`
	Status                         string                            `json:"status"`
	Network                        string                            `json:"network"`
	Subnetwork                     string                            `json:"subnetwork"`
	CurrentMasterVersion           string                            `json:"currentMasterVersion"`
	ResourceLabels                 map[string]string                 `json:"resourceLabels"`
	NodeConfig                     GKEClusterNodeConfig              `json:"nodeConfig"`
	PrivateClusterConfig           GKEPrivateClusterConfig           `json:"privateClusterConfig"`
	MasterAuthorizedNetworksConfig GKEMasterAuthorizedNetworksConfig `json:"masterAuthorizedNetworksConfig"`
	DatabaseEncryption             GKEDatabaseEncryption             `json:"databaseEncryption"`
	Raw                            json.RawMessage                   `json:"-"`
}

type GKEClusterNodeConfig struct {
	ServiceAccount string            `json:"serviceAccount"`
	Tags           []string          `json:"tags"`
	Labels         map[string]string `json:"labels"`
}

type GKEPrivateClusterConfig struct {
	EnablePrivateNodes    bool   `json:"enablePrivateNodes"`
	EnablePrivateEndpoint bool   `json:"enablePrivateEndpoint"`
	MasterIpv4CidrBlock   string `json:"masterIpv4CidrBlock"`
}

type GKEMasterAuthorizedNetworksConfig struct {
	Enabled    bool           `json:"enabled"`
	CidrBlocks []GKECIDRBlock `json:"cidrBlocks"`
}

type GKECIDRBlock struct {
	CidrBlock   string `json:"cidrBlock"`
	DisplayName string `json:"displayName"`
}

type GKEDatabaseEncryption struct {
	State   string `json:"state"`
	KeyName string `json:"keyName"`
}

type GKENodePoolRecord struct {
	Name             string                 `json:"name"`
	SelfLink         string                 `json:"selfLink"`
	Version          string                 `json:"version"`
	Status           string                 `json:"status"`
	Locations        []string               `json:"locations"`
	InitialNodeCount int                    `json:"initialNodeCount"`
	Config           GKENodePoolConfig      `json:"config"`
	Management       GKENodePoolManagement  `json:"management"`
	Autoscaling      GKENodePoolAutoscaling `json:"autoscaling"`
	ClusterName      string
	ClusterLocation  string
	Raw              json.RawMessage `json:"-"`
}

type GKENodePoolConfig struct {
	MachineType              string                    `json:"machineType"`
	DiskType                 string                    `json:"diskType"`
	DiskSizeGB               int                       `json:"diskSizeGb"`
	ImageType                string                    `json:"imageType"`
	ServiceAccount           string                    `json:"serviceAccount"`
	Tags                     []string                  `json:"tags"`
	Labels                   map[string]string         `json:"labels"`
	WorkloadMetadataConfig   GKEWorkloadMetadataConfig `json:"workloadMetadataConfig"`
	ShieldedInstanceConfig   GKEShieldedInstanceConfig `json:"shieldedInstanceConfig"`
	BootDiskKMSCryptoKeyName string                    `json:"bootDiskKmsKey"`
}

type GKEWorkloadMetadataConfig struct {
	Mode string `json:"mode"`
}

type GKEShieldedInstanceConfig struct {
	EnableSecureBoot          bool `json:"enableSecureBoot"`
	EnableIntegrityMonitoring bool `json:"enableIntegrityMonitoring"`
}

type GKENodePoolManagement struct {
	AutoRepair  bool `json:"autoRepair"`
	AutoUpgrade bool `json:"autoUpgrade"`
}

type GKENodePoolAutoscaling struct {
	Enabled      bool `json:"enabled"`
	MinNodeCount int  `json:"minNodeCount"`
	MaxNodeCount int  `json:"maxNodeCount"`
}

func VPCAccessConnectorEvent(settings Settings, record VPCAccessConnectorRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	attributes := cloudResourceAttributes(settings, "vpc_access_connector", record.Name, lastPathSegment(record.Name), "vpc_access_connector", location, nil)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["ip_cidr_range"] = record.IPCIDRRange
	attributes["state"] = record.State
	attributes["ready"] = boolString(strings.EqualFold(record.State, "READY"))
	attributes["machine_type"] = record.MachineType
	attributes["min_instances"] = strconv.Itoa(record.MinInstances)
	attributes["max_instances"] = strconv.Itoa(record.MaxInstances)
	attributes["min_throughput_mbps"] = strconv.Itoa(record.MinThroughput)
	attributes["max_throughput_mbps"] = strconv.Itoa(record.MaxThroughput)
	attributes["connected_projects"] = strings.Join(record.ConnectedProjects, ",")
	attributes["connected_projects_count"] = strconv.Itoa(len(record.ConnectedProjects))
	attributes["subnet"] = record.Subnet.Name
	attributes["subnet_project_id"] = record.Subnet.ProjectID
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-vpc-access-connector-"+record.Name, "gcp.vpc_access_connector", "gcp/vpc_access_connector/v1", payload, attributes)
}

func ComputeInstanceEvent(settings Settings, record ComputeInstanceRecord) (*primitives.Event, error) {
	location := lastPathSegment(record.Zone)
	network := firstComputeNetworkInterface(record)
	publicIP := computePublicIP(record)
	serviceAccountEmail := firstComputeServiceAccountEmail(record)
	attributes := cloudResourceAttributes(settings, "compute_instance", firstNonEmpty(record.ID, record.Name), record.Name, "compute_instance", location, record.Labels)
	attributes["zone"] = location
	attributes["machine_type"] = lastPathSegment(record.MachineType)
	attributes["status"] = record.Status
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["network"] = lastPathSegment(network.Network)
	attributes["network_url"] = network.Network
	attributes["subnet"] = lastPathSegment(network.Subnetwork)
	attributes["subnet_url"] = network.Subnetwork
	attributes["private_ip"] = network.NetworkIP
	attributes["public_ip"] = publicIP
	attributes["public"] = boolString(publicIP != "")
	attributes["internet_exposed"] = boolString(publicIP != "")
	attributes["external_exposure"] = boolString(publicIP != "")
	attributes["network_tags"] = strings.Join(record.Tags.Items, ",")
	attributes["security_tags"] = strings.Join(record.Tags.Items, ",")
	attributes["kms_key_name"] = computeInstanceKMSKey(record)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-"+firstNonEmpty(record.ID, record.Name), "gcp.compute_instance", "gcp/compute_instance/v1", payload, attributes)
}

func ComputeAddressEvent(settings Settings, record ComputeAddressRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name, record.Address)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	external := computeAddressExternal(record.AddressType)
	inUse := strings.EqualFold(record.Status, "IN_USE")
	usedBy := lastPathSegments(record.Users)
	attributes := cloudResourceAttributes(settings, "compute_address", resourceID, record.Name, "compute_address", location, record.Labels)
	attributes["description"] = record.Description
	attributes["ip_address"] = record.Address
	attributes["address"] = record.Address
	if record.PrefixLength > 0 {
		attributes["prefix_length"] = strconv.Itoa(record.PrefixLength)
	}
	attributes["status"] = record.Status
	attributes["reserved"] = boolString(strings.EqualFold(record.Status, "RESERVED"))
	attributes["in_use"] = boolString(inUse)
	attributes["network_tier"] = record.NetworkTier
	attributes["ip_version"] = record.IPVersion
	attributes["address_type"] = record.AddressType
	attributes["type"] = record.AddressType
	attributes["purpose"] = record.Purpose
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["users"] = strings.Join(usedBy, ",")
	attributes["user_urls"] = strings.Join(record.Users, ",")
	attributes["used_by"] = strings.Join(usedBy, ",")
	attributes["used_by_urls"] = strings.Join(record.Users, ",")
	attributes["users_count"] = strconv.Itoa(len(record.Users))
	attributes["ipv6_endpoint_type"] = record.IPv6EndpointType
	attributes["ip_collection"] = record.IPCollection
	attributes["public"] = boolString(external)
	attributes["internet_exposed"] = boolString(external && inUse)
	attributes["external_exposure"] = boolString(external && inUse)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-address-"+resourceID, "gcp.compute_address", "gcp/compute_address/v1", payload, attributes)
}

func ComputeBackendBucketEvent(settings Settings, record ComputeBackendBucketRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name, record.BucketName)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	usedByNames, usedByURLs := computeBackendBucketUsedBy(record.UsedBy)
	negativeCachingCodes := computeBackendBucketNegativeCachingCodes(record.CDNPolicy.NegativeCachingPolicy)
	attributes := cloudResourceAttributes(settings, "compute_backend_bucket", resourceID, record.Name, "compute_backend_bucket", location, nil)
	attributes["description"] = record.Description
	attributes["bucket_name"] = record.BucketName
	attributes["storage_bucket"] = record.BucketName
	attributes["cdn_enabled"] = boolString(record.EnableCDN)
	attributes["cache_mode"] = record.CDNPolicy.CacheMode
	attributes["signed_url_keys_count"] = strconv.Itoa(len(record.CDNPolicy.SignedURLKeyNames))
	attributes["signed_url_cache_max_age_sec"] = record.CDNPolicy.SignedURLCacheMaxAge
	attributes["request_coalescing"] = boolString(record.CDNPolicy.RequestCoalescing)
	if record.CDNPolicy.DefaultTTL != 0 {
		attributes["default_ttl_sec"] = strconv.Itoa(record.CDNPolicy.DefaultTTL)
	}
	if record.CDNPolicy.MaxTTL != 0 {
		attributes["max_ttl_sec"] = strconv.Itoa(record.CDNPolicy.MaxTTL)
	}
	if record.CDNPolicy.ClientTTL != 0 {
		attributes["client_ttl_sec"] = strconv.Itoa(record.CDNPolicy.ClientTTL)
	}
	attributes["negative_caching"] = boolString(record.CDNPolicy.NegativeCaching)
	attributes["negative_caching_policy_count"] = strconv.Itoa(len(record.CDNPolicy.NegativeCachingPolicy))
	attributes["negative_caching_codes"] = strings.Join(negativeCachingCodes, ",")
	if record.CDNPolicy.ServeWhileStale != 0 {
		attributes["serve_while_stale_sec"] = strconv.Itoa(record.CDNPolicy.ServeWhileStale)
	}
	attributes["bypass_cache_headers_count"] = strconv.Itoa(len(record.CDNPolicy.BypassCacheOnHeaders))
	attributes["cache_key_query_whitelist_count"] = strconv.Itoa(len(record.CDNPolicy.CacheKeyPolicy.QueryStringWhitelist))
	attributes["cache_key_include_headers_count"] = strconv.Itoa(len(record.CDNPolicy.CacheKeyPolicy.IncludeHTTPHeaders))
	attributes["custom_response_headers_count"] = strconv.Itoa(len(record.CustomResponseHeaders))
	attributes["edge_security_policy"] = lastPathSegment(record.EdgeSecurityPolicy)
	attributes["edge_security_policy_url"] = record.EdgeSecurityPolicy
	attributes["compression_mode"] = record.CompressionMode
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["used_by"] = strings.Join(usedByNames, ",")
	attributes["used_by_urls"] = strings.Join(usedByURLs, ",")
	attributes["used_by_count"] = strconv.Itoa(len(record.UsedBy))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-backend-bucket-"+resourceID, "gcp.compute_backend_bucket", "gcp/compute_backend_bucket/v1", payload, attributes)
}

func ComputeBackendServiceEvent(settings Settings, record ComputeBackendServiceRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	external := computeBackendServiceExternal(record.LoadBalancingScheme)
	backendNames, backendURLs, balancingModes, failoverCount := computeBackendServiceBackends(record.Backends)
	healthCheckNames := lastPathSegments(record.HealthChecks)
	attributes := cloudResourceAttributes(settings, "compute_backend_service", resourceID, record.Name, "compute_backend_service", location, record.Labels)
	attributes["description"] = record.Description
	attributes["protocol"] = record.Protocol
	attributes["port_name"] = record.PortName
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["external_load_balancing"] = boolString(external)
	attributes["session_affinity"] = record.SessionAffinity
	attributes["locality_lb_policy"] = record.LocalityLBPolicy
	attributes["timeout_sec"] = strconv.Itoa(record.TimeoutSec)
	attributes["connection_draining_timeout_sec"] = strconv.Itoa(record.ConnectionDraining.DrainingTimeoutSec)
	attributes["cdn_enabled"] = boolString(record.EnableCDN)
	attributes["iap_enabled"] = boolString(record.IAP.Enabled)
	attributes["logging_enabled"] = boolString(record.LogConfig.Enable)
	attributes["log_sample_rate"] = strconv.FormatFloat(record.LogConfig.SampleRate, 'f', -1, 64)
	attributes["health_checks"] = strings.Join(healthCheckNames, ",")
	attributes["health_check_urls"] = strings.Join(record.HealthChecks, ",")
	attributes["health_checks_count"] = strconv.Itoa(len(record.HealthChecks))
	attributes["backend_groups"] = strings.Join(backendNames, ",")
	attributes["backend_group_urls"] = strings.Join(backendURLs, ",")
	attributes["backends_count"] = strconv.Itoa(len(record.Backends))
	attributes["backend_balancing_modes"] = strings.Join(balancingModes, ",")
	attributes["failover_backends_count"] = strconv.Itoa(failoverCount)
	attributes["security_policy"] = lastPathSegment(record.SecurityPolicy)
	attributes["security_policy_url"] = record.SecurityPolicy
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["custom_request_headers_count"] = strconv.Itoa(len(record.CustomRequestHeaders))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-backend-service-"+resourceID, "gcp.compute_backend_service", "gcp/compute_backend_service/v1", payload, attributes)
}

func ComputeInstanceGroupEvent(settings Settings, record ComputeInstanceGroupRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	if location == "" {
		location = "global"
	}
	namedPorts := computeNamedPorts(record.NamedPorts)
	attributes := cloudResourceAttributes(settings, "compute_instance_group", resourceID, record.Name, "compute_instance_group", location, nil)
	attributes["description"] = record.Description
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = lastPathSegment(record.Region)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["size"] = strconv.Itoa(record.Size)
	attributes["named_ports"] = strings.Join(namedPorts, ",")
	attributes["named_ports_count"] = strconv.Itoa(len(record.NamedPorts))
	attributes["backend_group_type"] = "instance_group"
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-group-"+resourceID, "gcp.compute_instance_group", "gcp/compute_instance_group/v1", payload, attributes)
}

func ComputeInstanceGroupManagerEvent(settings Settings, record ComputeInstanceGroupManagerRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	if location == "" {
		location = "global"
	}
	namedPorts := computeNamedPorts(record.NamedPorts)
	healthChecks := computeAutoHealingHealthChecks(record.AutoHealingPolicies)
	attributes := cloudResourceAttributes(settings, "compute_instance_group_manager", resourceID, record.Name, "compute_instance_group_manager", location, nil)
	attributes["description"] = record.Description
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = lastPathSegment(record.Region)
	attributes["base_instance_name"] = record.BaseInstanceName
	attributes["instance_template"] = lastPathSegment(record.InstanceTemplate)
	attributes["instance_template_url"] = record.InstanceTemplate
	attributes["target_size"] = strconv.Itoa(record.TargetSize)
	attributes["target_pools"] = strings.Join(lastPathSegments(record.TargetPools), ",")
	attributes["target_pool_urls"] = strings.Join(record.TargetPools, ",")
	attributes["target_pools_count"] = strconv.Itoa(len(record.TargetPools))
	attributes["named_ports"] = strings.Join(namedPorts, ",")
	attributes["named_ports_count"] = strconv.Itoa(len(record.NamedPorts))
	attributes["auto_healing_health_checks"] = strings.Join(lastPathSegments(healthChecks), ",")
	attributes["auto_healing_health_check_urls"] = strings.Join(healthChecks, ",")
	attributes["auto_healing_policies_count"] = strconv.Itoa(len(record.AutoHealingPolicies))
	attributes["current_none"] = strconv.Itoa(record.CurrentActions.None)
	attributes["is_stable"] = boolString(record.Status.IsStable)
	attributes["version_target_reached"] = boolString(record.Status.VersionTarget.IsReached)
	attributes["update_policy_type"] = record.UpdatePolicy.Type
	attributes["minimal_action"] = record.UpdatePolicy.MinimalAction
	attributes["replacement_method"] = record.UpdatePolicy.ReplacementMethod
	attributes["distribution_zones"] = strings.Join(computeDistributionZones(record.DistributionPolicy), ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-group-manager-"+resourceID, "gcp.compute_instance_group_manager", "gcp/compute_instance_group_manager/v1", payload, attributes)
}

func ComputeInstanceTemplateEvent(settings Settings, record ComputeInstanceTemplateRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	network := firstTemplateNetworkInterface(record.Properties)
	serviceAccounts := computeTemplateServiceAccounts(record.Properties)
	public := computeTemplatePublic(record.Properties)
	attributes := cloudResourceAttributes(settings, "compute_instance_template", resourceID, record.Name, "compute_instance_template", "global", record.Properties.Labels)
	attributes["description"] = record.Description
	attributes["machine_type"] = lastPathSegment(record.Properties.MachineType)
	attributes["network"] = lastPathSegment(network.Network)
	attributes["network_url"] = network.Network
	attributes["subnet"] = lastPathSegment(network.Subnetwork)
	attributes["subnet_url"] = network.Subnetwork
	attributes["subnetwork"] = lastPathSegment(network.Subnetwork)
	attributes["subnetwork_url"] = network.Subnetwork
	attributes["service_account_email"] = firstString(serviceAccounts)
	attributes["service_accounts"] = strings.Join(serviceAccounts, ",")
	attributes["service_accounts_count"] = strconv.Itoa(len(serviceAccounts))
	attributes["runtime_identity"] = firstString(serviceAccounts)
	attributes["network_tags"] = strings.Join(record.Properties.Tags.Items, ",")
	attributes["security_tags"] = strings.Join(record.Properties.Tags.Items, ",")
	attributes["disks_count"] = strconv.Itoa(len(record.Properties.Disks))
	attributes["kms_key_name"] = computeTemplateBootDiskKMS(record.Properties)
	attributes["secure_boot"] = boolString(record.Properties.ShieldedInstanceConfig.EnableSecureBoot)
	attributes["integrity_monitoring"] = boolString(record.Properties.ShieldedInstanceConfig.EnableIntegrityMonitoring)
	attributes["public"] = boolString(public)
	attributes["internet_exposed"] = boolString(public)
	attributes["external_exposure"] = boolString(public)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-template-"+resourceID, "gcp.compute_instance_template", "gcp/compute_instance_template/v1", payload, attributes)
}

func ComputeNetworkEndpointGroupEvent(settings Settings, record ComputeNetworkEndpointGroupRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	if location == "" {
		location = "global"
	}
	attributes := cloudResourceAttributes(settings, "compute_network_endpoint_group", resourceID, record.Name, "compute_network_endpoint_group", location, record.Annotations)
	attributes["description"] = record.Description
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = lastPathSegment(record.Region)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["network_endpoint_type"] = record.NetworkEndpointType
	attributes["endpoint_type"] = record.NetworkEndpointType
	attributes["default_port"] = strconv.Itoa(record.DefaultPort)
	attributes["size"] = strconv.Itoa(record.Size)
	attributes["psc_target_service"] = record.PscTargetService
	attributes["cloud_run_service"] = record.CloudRun.Service
	attributes["cloud_function"] = record.CloudFunction.Function
	attributes["app_engine_service"] = record.AppEngine.Service
	attributes["backend_group_type"] = "network_endpoint_group"
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-network-endpoint-group-"+resourceID, "gcp.compute_network_endpoint_group", "gcp/compute_network_endpoint_group/v1", payload, attributes)
}

func ComputeRouterEvent(settings Settings, record ComputeRouterRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	natNames, natIPs, natModes, natLogging := computeRouterNATs(record.NATs)
	interfaces := computeRouterInterfaces(record.Interfaces)
	peerNames, peerASNs := computeRouterPeers(record.BGPPeers)
	attributes := cloudResourceAttributes(settings, "compute_router", resourceID, record.Name, "compute_router", location, nil)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["ncc_gateway"] = lastPathSegment(record.NCCGateway)
	attributes["ncc_gateway_url"] = record.NCCGateway
	attributes["asn"] = strconv.FormatInt(record.BGP.ASN, 10)
	attributes["advertise_mode"] = record.BGP.AdvertiseMode
	attributes["advertised_groups"] = strings.Join(record.BGP.AdvertisedGroups, ",")
	attributes["keepalive_interval"] = strconv.Itoa(record.BGP.KeepaliveInterval)
	attributes["interfaces"] = strings.Join(interfaces, ",")
	attributes["interfaces_count"] = strconv.Itoa(len(record.Interfaces))
	attributes["bgp_peers"] = strings.Join(peerNames, ",")
	attributes["bgp_peer_asns"] = strings.Join(peerASNs, ",")
	attributes["bgp_peers_count"] = strconv.Itoa(len(record.BGPPeers))
	attributes["nats"] = strings.Join(natNames, ",")
	attributes["nats_count"] = strconv.Itoa(len(record.NATs))
	attributes["nat_ip_allocate_options"] = strings.Join(natModes, ",")
	attributes["nat_ips"] = strings.Join(lastPathSegments(natIPs), ",")
	attributes["nat_ip_urls"] = strings.Join(natIPs, ",")
	attributes["nat_logging_enabled"] = boolString(natLogging)
	attributes["encrypted_interconnect_router"] = boolString(record.EncryptedInterconnectRouter)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-router-"+resourceID, "gcp.compute_router", "gcp/compute_router/v1", payload, attributes)
}

func ComputeVPNGatewayEvent(settings Settings, record ComputeVPNGatewayRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_vpn_gateway", resourceID, record.Name, "compute_vpn_gateway", location, record.Labels)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["gateway_ip_version"] = record.GatewayIPVersion
	attributes["stack_type"] = record.StackType
	attributes["interfaces_count"] = strconv.Itoa(len(record.VPNInterfaces))
	attributes["interface_ips"] = strings.Join(computeVPNGatewayInterfaceIPs(record.VPNInterfaces), ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-vpn-gateway-"+resourceID, "gcp.compute_vpn_gateway", "gcp/compute_vpn_gateway/v1", payload, attributes)
}

func ComputeTargetVPNGatewayEvent(settings Settings, record ComputeTargetVPNGatewayRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_target_vpn_gateway", resourceID, record.Name, "compute_target_vpn_gateway", location, record.Labels)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["status"] = record.Status
	attributes["tunnels"] = strings.Join(lastPathSegments(record.Tunnels), ",")
	attributes["tunnel_urls"] = strings.Join(record.Tunnels, ",")
	attributes["tunnels_count"] = strconv.Itoa(len(record.Tunnels))
	attributes["forwarding_rules"] = strings.Join(lastPathSegments(record.ForwardingRules), ",")
	attributes["forwarding_rule_urls"] = strings.Join(record.ForwardingRules, ",")
	attributes["forwarding_rules_count"] = strconv.Itoa(len(record.ForwardingRules))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-vpn-gateway-"+resourceID, "gcp.compute_target_vpn_gateway", "gcp/compute_target_vpn_gateway/v1", payload, attributes)
}

func ComputeVPNTunnelEvent(settings Settings, record ComputeVPNTunnelRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_vpn_tunnel", resourceID, record.Name, "compute_vpn_tunnel", location, record.Labels)
	attributes["description"] = record.Description
	attributes["status"] = record.Status
	attributes["detailed_status"] = record.DetailedStatus
	attributes["ike_version"] = strconv.Itoa(record.IKEVersion)
	attributes["peer_ip"] = record.PeerIP
	attributes["peer_external_gateway"] = lastPathSegment(record.PeerExternalGateway)
	attributes["peer_external_gateway_url"] = record.PeerExternalGateway
	attributes["peer_gcp_gateway"] = lastPathSegment(record.PeerGCPGateway)
	attributes["peer_gcp_gateway_url"] = record.PeerGCPGateway
	attributes["target_vpn_gateway"] = lastPathSegment(record.TargetVPNGateway)
	attributes["target_vpn_gateway_url"] = record.TargetVPNGateway
	attributes["vpn_gateway"] = lastPathSegment(record.VPNGateway)
	attributes["vpn_gateway_url"] = record.VPNGateway
	attributes["vpn_gateway_interface"] = strconv.Itoa(record.VPNGatewayInterface)
	attributes["router"] = lastPathSegment(record.Router)
	attributes["router_url"] = record.Router
	attributes["local_traffic_selectors"] = strings.Join(record.LocalTrafficSelector, ",")
	attributes["remote_traffic_selectors"] = strings.Join(record.RemoteTrafficSelector, ",")
	attributes["shared_secret_configured"] = boolString(record.SharedSecretHash != "")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-vpn-tunnel-"+resourceID, "gcp.compute_vpn_tunnel", "gcp/compute_vpn_tunnel/v1", payload, attributes)
}

func ComputeInterconnectAttachmentEvent(settings Settings, record ComputeInterconnectAttachmentRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_interconnect_attachment", resourceID, record.Name, "compute_interconnect_attachment", location, record.Labels)
	attributes["description"] = record.Description
	attributes["router"] = lastPathSegment(record.Router)
	attributes["router_url"] = record.Router
	attributes["interconnect"] = lastPathSegment(record.Interconnect)
	attributes["interconnect_url"] = record.Interconnect
	attributes["attachment_type"] = record.Type
	attributes["type"] = record.Type
	attributes["admin_enabled"] = boolString(record.AdminEnabled)
	attributes["operational_status"] = record.OperationalStatus
	attributes["status"] = firstNonEmpty(record.OperationalStatus, record.State)
	attributes["state"] = record.State
	attributes["bandwidth"] = record.Bandwidth
	attributes["edge_availability_domain"] = record.EdgeAvailabilityDomain
	if record.VlanTag8021q != 0 {
		attributes["vlan_tag_8021q"] = strconv.Itoa(record.VlanTag8021q)
	}
	if record.MTU != 0 {
		attributes["mtu"] = strconv.Itoa(record.MTU)
	}
	attributes["encryption"] = record.Encryption
	attributes["encrypted"] = boolString(record.Encryption != "" && !strings.EqualFold(record.Encryption, "NONE"))
	attributes["stack_type"] = record.StackType
	attributes["cloud_router_ip_address"] = record.CloudRouterIPAddress
	attributes["customer_router_ip_address"] = record.CustomerRouterIPAddress
	attributes["ipsec_internal_addresses"] = strings.Join(lastPathSegments(record.IPSecInternalAddresses), ",")
	attributes["ipsec_internal_address_urls"] = strings.Join(record.IPSecInternalAddresses, ",")
	attributes["satisfies_pzs"] = boolString(record.SatisfiesPzs)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-interconnect-attachment-"+resourceID, "gcp.compute_interconnect_attachment", "gcp/compute_interconnect_attachment/v1", payload, attributes)
}

func ComputeExternalVPNGatewayEvent(settings Settings, record ComputeExternalVPNGatewayRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	ipv4, ipv6 := computeExternalVPNGatewayInterfaceIPs(record.Interfaces)
	attributes := cloudResourceAttributes(settings, "compute_external_vpn_gateway", resourceID, record.Name, "compute_external_vpn_gateway", "global", record.Labels)
	attributes["description"] = record.Description
	attributes["redundancy_type"] = record.RedundancyType
	attributes["interfaces_count"] = strconv.Itoa(len(record.Interfaces))
	attributes["interface_ips"] = strings.Join(ipv4, ",")
	attributes["interface_ipv6_addresses"] = strings.Join(ipv6, ",")
	attributes["public"] = boolString(len(ipv4) != 0 || len(ipv6) != 0)
	attributes["external_exposure"] = boolString(len(ipv4) != 0 || len(ipv6) != 0)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-external-vpn-gateway-"+resourceID, "gcp.compute_external_vpn_gateway", "gcp/compute_external_vpn_gateway/v1", payload, attributes)
}

func ComputeInterconnectEvent(settings Settings, record ComputeInterconnectRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := "global"
	attachments := lastPathSegments(record.InterconnectAttachments)
	outages := computeInterconnectOutages(record.ExpectedOutages)
	attributes := cloudResourceAttributes(settings, "compute_interconnect", resourceID, record.Name, "compute_interconnect", location, record.Labels)
	attributes["description"] = record.Description
	attributes["interconnect_location"] = lastPathSegment(record.Location)
	attributes["interconnect_location_url"] = record.Location
	attributes["remote_location"] = lastPathSegment(record.RemoteLocation)
	attributes["remote_location_url"] = record.RemoteLocation
	attributes["link_type"] = record.LinkType
	attributes["interconnect_type"] = record.InterconnectType
	attributes["admin_enabled"] = boolString(record.AdminEnabled)
	attributes["operational_status"] = record.OperationalStatus
	attributes["status"] = firstNonEmpty(record.OperationalStatus, record.State)
	attributes["state"] = record.State
	attributes["requested_link_count"] = strconv.Itoa(record.RequestedLinkCount)
	attributes["provisioned_link_count"] = strconv.Itoa(record.ProvisionedLinkCount)
	attributes["attachments"] = strings.Join(attachments, ",")
	attributes["attachment_urls"] = strings.Join(record.InterconnectAttachments, ",")
	attributes["attachments_count"] = strconv.Itoa(len(record.InterconnectAttachments))
	attributes["peer_ip_address"] = record.PeerIPAddress
	attributes["google_ip_address"] = record.GoogleIPAddress
	attributes["expected_outages"] = strings.Join(outages, ",")
	attributes["expected_outages_count"] = strconv.Itoa(len(record.ExpectedOutages))
	attributes["macsec_enabled"] = boolString(record.MACsecEnabled)
	attributes["macsec_fail_open"] = boolString(record.MACsec.FailOpen)
	attributes["satisfies_pzs"] = boolString(record.SatisfiesPzs)
	attributes["requested_features"] = strings.Join(record.RequestedFeatures, ",")
	attributes["available_features"] = strings.Join(record.AvailableFeatures, ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-interconnect-"+resourceID, "gcp.compute_interconnect", "gcp/compute_interconnect/v1", payload, attributes)
}

func ComputePacketMirroringEvent(settings Settings, record ComputePacketMirroringRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	network := computePacketMirroringReferenceURL(record.Network)
	collector := firstNonEmpty(record.CollectorILB.CanonicalURL, record.CollectorILB.URL)
	instances := computePacketMirroringReferenceURLs(record.MirroredResources.Instances)
	subnetworks := computePacketMirroringReferenceURLs(record.MirroredResources.Subnetworks)
	enabled := !strings.EqualFold(record.Enable, "FALSE") && !strings.EqualFold(record.Enable, "DISABLED")
	attributes := cloudResourceAttributes(settings, "compute_packet_mirroring", resourceID, record.Name, "compute_packet_mirroring", location, nil)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(network)
	attributes["network_url"] = network
	attributes["priority"] = strconv.Itoa(record.Priority)
	attributes["collector_ilb"] = lastPathSegment(collector)
	attributes["collector_ilb_url"] = collector
	attributes["mirrored_instances"] = strings.Join(lastPathSegments(instances), ",")
	attributes["mirrored_instance_urls"] = strings.Join(instances, ",")
	attributes["mirrored_subnetworks"] = strings.Join(lastPathSegments(subnetworks), ",")
	attributes["mirrored_subnetwork_urls"] = strings.Join(subnetworks, ",")
	attributes["mirrored_tags"] = strings.Join(record.MirroredResources.Tags, ",")
	attributes["filter_cidr_ranges"] = strings.Join(record.Filter.CIDRRanges, ",")
	attributes["filter_protocols"] = strings.Join(record.Filter.IPProtocols, ",")
	attributes["filter_direction"] = record.Filter.Direction
	attributes["enable"] = record.Enable
	attributes["enabled"] = boolString(enabled)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-packet-mirroring-"+resourceID, "gcp.compute_packet_mirroring", "gcp/compute_packet_mirroring/v1", payload, attributes)
}

func computePacketMirroringReferenceURL(ref ComputePacketMirroringReference) string {
	return firstNonEmpty(ref.CanonicalURL, ref.URL)
}

func computePacketMirroringReferenceURLs(refs []ComputePacketMirroringReference) []string {
	urls := make([]string, 0, len(refs))
	for _, ref := range refs {
		if url := computePacketMirroringReferenceURL(ref); url != "" {
			urls = append(urls, url)
		}
	}
	return urls
}

func ComputeNetworkFirewallPolicyEvent(settings Settings, record ComputeNetworkFirewallPolicyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.SelfLinkWithID, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	summary := computeFirewallPolicyRuleSummary(record.Rules)
	attributes := cloudResourceAttributes(settings, "compute_network_firewall_policy", resourceID, firstNonEmpty(record.DisplayName, record.ShortName, record.Name), "compute_network_firewall_policy", location, nil)
	attributes["description"] = record.Description
	attributes["policy_type"] = record.PolicyType
	attributes["parent"] = record.Parent
	attributes["short_name"] = record.ShortName
	attributes["display_name"] = record.DisplayName
	attributes["rules_count"] = strconv.Itoa(len(record.Rules))
	attributes["packet_mirroring_rules_count"] = strconv.Itoa(len(record.PacketMirroringRules))
	attributes["associations"] = strings.Join(computeFirewallPolicyAssociations(record.Associations), ",")
	attributes["associations_count"] = strconv.Itoa(len(record.Associations))
	attributes["rule_actions"] = strings.Join(summary.Actions, ",")
	attributes["rule_priorities"] = strings.Join(summary.Priorities, ",")
	attributes["source_ranges"] = strings.Join(summary.SourceRanges, ",")
	attributes["destination_ranges"] = strings.Join(summary.DestinationRanges, ",")
	attributes["layer4_configs"] = strings.Join(summary.Layer4Configs, ",")
	attributes["target_resources"] = strings.Join(summary.TargetResources, ",")
	attributes["target_service_accounts"] = strings.Join(summary.TargetServiceAccounts, ",")
	attributes["logging_enabled"] = boolString(summary.LoggingEnabled)
	attributes["disabled_rules_count"] = strconv.Itoa(summary.DisabledCount)
	if record.RuleTupleCount != 0 {
		attributes["rule_tuple_count"] = strconv.Itoa(record.RuleTupleCount)
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-network-firewall-policy-"+resourceID, "gcp.compute_network_firewall_policy", "gcp/compute_network_firewall_policy/v1", payload, attributes)
}

func ComputeHealthCheckEvent(settings Settings, record ComputeHealthCheckRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	healthCheckType, probe := computeHealthCheckProbe(record)
	attributes := cloudResourceAttributes(settings, "compute_health_check", resourceID, record.Name, "compute_health_check", location, nil)
	attributes["description"] = record.Description
	attributes["type"] = healthCheckType
	attributes["protocol"] = healthCheckType
	attributes["check_interval_sec"] = strconv.Itoa(record.CheckIntervalSec)
	attributes["timeout_sec"] = strconv.Itoa(record.TimeoutSec)
	attributes["healthy_threshold"] = strconv.Itoa(record.HealthyThreshold)
	attributes["unhealthy_threshold"] = strconv.Itoa(record.UnhealthyThreshold)
	if probe.Port != 0 {
		attributes["port"] = strconv.Itoa(probe.Port)
	}
	attributes["port_name"] = probe.PortName
	attributes["port_specification"] = probe.PortSpecification
	attributes["host"] = probe.Host
	attributes["request_path"] = probe.RequestPath
	attributes["proxy_header"] = probe.ProxyHeader
	attributes["grpc_service_name"] = probe.GRPCServiceName
	attributes["request_configured"] = boolString(probe.Request != "")
	attributes["response_configured"] = boolString(probe.Response != "")
	attributes["source_regions"] = strings.Join(record.SourceRegions, ",")
	attributes["source_regions_count"] = strconv.Itoa(len(record.SourceRegions))
	attributes["logging_enabled"] = boolString(record.LogConfig.Enable)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-health-check-"+resourceID, "gcp.compute_health_check", "gcp/compute_health_check/v1", payload, attributes)
}

func ComputeSecurityPolicyEvent(settings Settings, record ComputeSecurityPolicyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	rules := computeSecurityPolicyRules(record.Rules)
	associatedNames, associatedURLs := computeSecurityPolicyAssociations(record.Associations)
	attributes := cloudResourceAttributes(settings, "compute_security_policy", resourceID, record.Name, "compute_security_policy", location, record.Labels)
	attributes["description"] = record.Description
	attributes["security_policy_type"] = record.Type
	attributes["policy_type"] = record.Type
	attributes["fingerprint"] = record.Fingerprint
	attributes["rules_count"] = strconv.Itoa(len(record.Rules))
	attributes["preview_rules_count"] = strconv.Itoa(rules.previewCount)
	attributes["allow_rules_count"] = strconv.Itoa(rules.allowCount)
	attributes["deny_rules_count"] = strconv.Itoa(rules.denyCount)
	attributes["throttle_rules_count"] = strconv.Itoa(rules.throttleCount)
	attributes["rate_based_ban_rules_count"] = strconv.Itoa(rules.rateBasedBanCount)
	attributes["redirect_rules_count"] = strconv.Itoa(rules.redirectCount)
	attributes["custom_expression_rules_count"] = strconv.Itoa(rules.customExpressionCount)
	attributes["default_rule_action"] = rules.defaultAction
	attributes["rule_actions"] = strings.Join(rules.actions, ",")
	attributes["versioned_expressions"] = strings.Join(rules.versionedExpressions, ",")
	attributes["source_ip_ranges"] = strings.Join(rules.sourceIPRanges, ",")
	attributes["custom_expressions"] = strings.Join(rules.customExpressions, "\n")
	attributes["adaptive_protection_enabled"] = boolString(record.AdaptiveProtectionConfig.Layer7DDoSDefenseConfig.Enable)
	attributes["json_parsing"] = record.AdvancedOptionsConfig.JSONParsing
	attributes["log_level"] = record.AdvancedOptionsConfig.LogLevel
	attributes["user_ip_request_headers"] = strings.Join(record.AdvancedOptionsConfig.UserIPRequestHeaders, ",")
	attributes["associations_count"] = strconv.Itoa(len(record.Associations))
	attributes["associated_resources"] = strings.Join(associatedNames, ",")
	attributes["associated_resource_urls"] = strings.Join(associatedURLs, ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-security-policy-"+resourceID, "gcp.compute_security_policy", "gcp/compute_security_policy/v1", payload, attributes)
}

func ComputeURLMapEvent(settings Settings, record ComputeURLMapRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	routes := computeURLMapRoutes(record)
	attributes := cloudResourceAttributes(settings, "compute_url_map", resourceID, record.Name, "compute_url_map", location, nil)
	attributes["description"] = record.Description
	attributes["default_service"] = lastPathSegment(record.DefaultService)
	attributes["default_service_url"] = record.DefaultService
	attributes["host_rules_count"] = strconv.Itoa(len(record.HostRules))
	attributes["hosts"] = strings.Join(routes.hosts, ",")
	attributes["path_matchers"] = strings.Join(routes.pathMatchers, ",")
	attributes["path_matchers_count"] = strconv.Itoa(len(record.PathMatchers))
	attributes["paths"] = strings.Join(routes.paths, ",")
	attributes["path_rules_count"] = strconv.Itoa(routes.pathRulesCount)
	attributes["route_rules_count"] = strconv.Itoa(routes.routeRulesCount)
	attributes["redirect_rules_count"] = strconv.Itoa(routes.redirectRulesCount)
	attributes["weighted_backend_services_count"] = strconv.Itoa(routes.weightedBackendServicesCount)
	attributes["backend_services"] = strings.Join(routes.backendNames, ",")
	attributes["backend_service_urls"] = strings.Join(routes.backendURLs, ",")
	attributes["backend_resources"] = strings.Join(routes.backendNames, ",")
	attributes["backend_resource_urls"] = strings.Join(routes.backendURLs, ",")
	attributes["tests_count"] = strconv.Itoa(len(record.Tests))
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-url-map-"+resourceID, "gcp.compute_url_map", "gcp/compute_url_map/v1", payload, attributes)
}

func ComputeTargetHTTPProxyEvent(settings Settings, record ComputeTargetHTTPProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	attributes := cloudResourceAttributes(settings, "compute_target_http_proxy", resourceID, record.Name, "compute_target_http_proxy", location, nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "HTTP"
	attributes["url_map"] = lastPathSegment(record.URLMap)
	attributes["url_map_url"] = record.URLMap
	attributes["proxy_bind"] = boolString(record.ProxyBind)
	if record.HTTPKeepAliveTimeoutSec != 0 {
		attributes["http_keep_alive_timeout_sec"] = strconv.Itoa(record.HTTPKeepAliveTimeoutSec)
	}
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-http-proxy-"+resourceID, "gcp.compute_target_http_proxy", "gcp/compute_target_http_proxy/v1", payload, attributes)
}

func ComputeTargetHTTPSProxyEvent(settings Settings, record ComputeTargetHTTPSProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	certificates := lastPathSegments(record.SSLCertificates)
	attributes := cloudResourceAttributes(settings, "compute_target_https_proxy", resourceID, record.Name, "compute_target_https_proxy", location, nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "HTTPS"
	attributes["url_map"] = lastPathSegment(record.URLMap)
	attributes["url_map_url"] = record.URLMap
	attributes["ssl_certificates"] = strings.Join(certificates, ",")
	attributes["ssl_certificate_urls"] = strings.Join(record.SSLCertificates, ",")
	attributes["ssl_certificates_count"] = strconv.Itoa(len(record.SSLCertificates))
	attributes["certificate_map"] = lastPathSegment(record.CertificateMap)
	attributes["certificate_map_url"] = record.CertificateMap
	attributes["certificates_configured"] = boolString(len(record.SSLCertificates) != 0 || record.CertificateMap != "")
	attributes["quic_override"] = record.QUICOverride
	attributes["ssl_policy"] = lastPathSegment(record.SSLPolicy)
	attributes["ssl_policy_url"] = record.SSLPolicy
	attributes["server_tls_policy"] = lastPathSegment(record.ServerTLSPolicy)
	attributes["server_tls_policy_url"] = record.ServerTLSPolicy
	attributes["authorization_policy"] = lastPathSegment(record.AuthorizationPolicy)
	attributes["authorization_policy_url"] = record.AuthorizationPolicy
	attributes["proxy_bind"] = boolString(record.ProxyBind)
	attributes["tls_enabled"] = "true"
	if record.HTTPKeepAliveTimeoutSec != 0 {
		attributes["http_keep_alive_timeout_sec"] = strconv.Itoa(record.HTTPKeepAliveTimeoutSec)
	}
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-https-proxy-"+resourceID, "gcp.compute_target_https_proxy", "gcp/compute_target_https_proxy/v1", payload, attributes)
}

func ComputeTargetSSLProxyEvent(settings Settings, record ComputeTargetSSLProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	certificates := lastPathSegments(record.SSLCertificates)
	attributes := cloudResourceAttributes(settings, "compute_target_ssl_proxy", resourceID, record.Name, "compute_target_ssl_proxy", "global", nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "SSL"
	attributes["backend_service"] = lastPathSegment(record.Service)
	attributes["backend_service_url"] = record.Service
	attributes["service"] = lastPathSegment(record.Service)
	attributes["service_url"] = record.Service
	attributes["ssl_certificates"] = strings.Join(certificates, ",")
	attributes["ssl_certificate_urls"] = strings.Join(record.SSLCertificates, ",")
	attributes["ssl_certificates_count"] = strconv.Itoa(len(record.SSLCertificates))
	attributes["certificate_map"] = lastPathSegment(record.CertificateMap)
	attributes["certificate_map_url"] = record.CertificateMap
	attributes["certificates_configured"] = boolString(len(record.SSLCertificates) != 0 || record.CertificateMap != "")
	attributes["ssl_policy"] = lastPathSegment(record.SSLPolicy)
	attributes["ssl_policy_url"] = record.SSLPolicy
	attributes["proxy_header"] = record.ProxyHeader
	attributes["tls_enabled"] = "true"
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-ssl-proxy-"+resourceID, "gcp.compute_target_ssl_proxy", "gcp/compute_target_ssl_proxy/v1", payload, attributes)
}

func ComputeTargetTCPProxyEvent(settings Settings, record ComputeTargetTCPProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	external := computeBackendServiceExternal(record.LoadBalancingScheme)
	attributes := cloudResourceAttributes(settings, "compute_target_tcp_proxy", resourceID, record.Name, "compute_target_tcp_proxy", location, nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "TCP"
	attributes["backend_service"] = lastPathSegment(record.Service)
	attributes["backend_service_url"] = record.Service
	attributes["service"] = lastPathSegment(record.Service)
	attributes["service_url"] = record.Service
	attributes["proxy_header"] = record.ProxyHeader
	attributes["proxy_bind"] = boolString(record.ProxyBind)
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["external_load_balancing"] = boolString(external)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-tcp-proxy-"+resourceID, "gcp.compute_target_tcp_proxy", "gcp/compute_target_tcp_proxy/v1", payload, attributes)
}

func ComputeTargetGRPCProxyEvent(settings Settings, record ComputeTargetGRPCProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_target_grpc_proxy", resourceID, record.Name, "compute_target_grpc_proxy", "global", nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "GRPC"
	attributes["url_map"] = lastPathSegment(record.URLMap)
	attributes["url_map_url"] = record.URLMap
	attributes["validate_for_proxyless"] = boolString(record.ValidateForProxyless)
	attributes["proxyless_validation"] = boolString(record.ValidateForProxyless)
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-grpc-proxy-"+resourceID, "gcp.compute_target_grpc_proxy", "gcp/compute_target_grpc_proxy/v1", payload, attributes)
}

func ComputeSSLPolicyEvent(settings Settings, record ComputeSSLPolicyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	attributes := cloudResourceAttributes(settings, "compute_ssl_policy", resourceID, record.Name, "compute_ssl_policy", location, nil)
	attributes["description"] = record.Description
	attributes["profile"] = record.Profile
	attributes["min_tls_version"] = record.MinTLSVersion
	attributes["enabled_features"] = strings.Join(record.EnabledFeatures, ",")
	attributes["enabled_features_count"] = strconv.Itoa(len(record.EnabledFeatures))
	attributes["custom_features"] = strings.Join(record.CustomFeatures, ",")
	attributes["custom_features_count"] = strconv.Itoa(len(record.CustomFeatures))
	attributes["custom_profile"] = boolString(strings.EqualFold(record.Profile, "CUSTOM"))
	attributes["post_quantum_key_exchange"] = record.PostQuantumKeyExchange
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-ssl-policy-"+resourceID, "gcp.compute_ssl_policy", "gcp/compute_ssl_policy/v1", payload, attributes)
}

func ComputeSSLCertificateEvent(settings Settings, record ComputeSSLCertificateRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	certificateType := firstNonEmpty(record.Type, computeSSLCertificateType(record))
	managedDomains := append([]string(nil), record.Managed.Domains...)
	domainStatuses := computeSSLCertificateDomainStatuses(record.Managed.DomainStatus)
	attributes := cloudResourceAttributes(settings, "compute_ssl_certificate", resourceID, record.Name, "compute_ssl_certificate", location, nil)
	attributes["description"] = record.Description
	attributes["certificate_type"] = certificateType
	attributes["type"] = certificateType
	attributes["managed"] = boolString(certificateType == "MANAGED" || len(managedDomains) != 0 || record.Managed.Status != "")
	attributes["self_managed"] = boolString(certificateType == "SELF_MANAGED" || record.SelfManaged.Certificate != "")
	attributes["managed_status"] = record.Managed.Status
	attributes["managed_domains"] = strings.Join(managedDomains, ",")
	attributes["managed_domains_count"] = strconv.Itoa(len(managedDomains))
	attributes["domain_statuses"] = strings.Join(domainStatuses, ",")
	attributes["subject_alternative_names"] = strings.Join(record.SubjectAlternativeNames, ",")
	attributes["sans"] = strings.Join(record.SubjectAlternativeNames, ",")
	attributes["san_count"] = strconv.Itoa(len(record.SubjectAlternativeNames))
	attributes["expire_time"] = record.ExpireTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-ssl-certificate-"+resourceID, "gcp.compute_ssl_certificate", "gcp/compute_ssl_certificate/v1", payload, attributes)
}

func ComputeNetworkEvent(settings Settings, record ComputeNetworkRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_network", resourceID, record.Name, "compute_network", "global", record.Labels)
	attributes["description"] = record.Description
	attributes["auto_create_subnetworks"] = boolString(record.AutoCreateSubnetworks)
	attributes["routing_mode"] = record.RoutingConfig.RoutingMode
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-network-"+resourceID, "gcp.compute_network", "gcp/compute_network/v1", payload, attributes)
}

func ComputeFirewallEvent(settings Settings, record ComputeFirewallRecord) (*primitives.Event, error) {
	allowed := computeFirewallPrimaryAllowed(record)
	attributes := cloudResourceAttributes(settings, "compute_firewall", firstNonEmpty(record.ID, record.Name), record.Name, "compute_firewall", "global", nil)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["direction"] = record.Direction
	attributes["disabled"] = boolString(record.Disabled)
	attributes["source_ranges"] = strings.Join(record.SourceRanges, ",")
	attributes["target_tags"] = strings.Join(record.TargetTags, ",")
	attributes["target_service_accounts"] = strings.Join(record.TargetServiceAccounts, ",")
	attributes["protocol"] = allowed.IPProtocol
	attributes["ports"] = strings.Join(allowed.Ports, ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-firewall-"+firstNonEmpty(record.ID, record.Name), "gcp.compute_firewall", "gcp/compute_firewall/v1", payload, attributes)
}

func ComputeRouteEvent(settings Settings, record ComputeRouteRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	nextHopType, nextHopURL, nextHop := computeRouteNextHop(record)
	defaultRoute := record.DestRange == "0.0.0.0/0" || record.DestRange == "::/0"
	internetEgress := defaultRoute && strings.Contains(nextHopURL, "default-internet-gateway")
	attributes := cloudResourceAttributes(settings, "compute_route", resourceID, record.Name, "compute_route", "global", nil)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["destination_range"] = record.DestRange
	attributes["dest_range"] = record.DestRange
	attributes["priority"] = strconv.Itoa(record.Priority)
	attributes["route_type"] = record.RouteType
	attributes["route_status"] = record.RouteStatus
	attributes["status"] = record.RouteStatus
	attributes["target_tags"] = strings.Join(record.Tags, ",")
	attributes["next_hop_type"] = nextHopType
	attributes["next_hop"] = nextHop
	attributes["next_hop_url"] = nextHopURL
	attributes["next_hop_ip"] = record.NextHopIP
	attributes["next_hop_origin"] = record.NextHopOrigin
	if record.NextHopMed != 0 {
		attributes["next_hop_med"] = strconv.Itoa(record.NextHopMed)
	}
	attributes["default_route"] = boolString(defaultRoute)
	attributes["internet_egress"] = boolString(internetEgress)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-route-"+resourceID, "gcp.compute_route", "gcp/compute_route/v1", payload, attributes)
}

func ComputeForwardingRuleEvent(settings Settings, record ComputeForwardingRuleRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	targetType, targetURL, targetName := computeForwardingRuleTarget(record)
	external := computeForwardingRuleExternal(record.LoadBalancingScheme)
	attributes := cloudResourceAttributes(settings, "compute_forwarding_rule", resourceID, record.Name, "compute_forwarding_rule", location, record.Labels)
	attributes["description"] = record.Description
	attributes["ip_address"] = record.IPAddress
	attributes["ip_protocol"] = record.IPProtocol
	attributes["ip_version"] = record.IPVersion
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["network_tier"] = record.NetworkTier
	attributes["port_range"] = record.PortRange
	attributes["ports"] = strings.Join(record.Ports, ",")
	attributes["all_ports"] = boolString(record.AllPorts)
	attributes["allow_global_access"] = boolString(record.AllowGlobalAccess)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["target_type"] = targetType
	attributes["target"] = targetName
	attributes["target_url"] = targetURL
	attributes["backend_service"] = lastPathSegment(record.BackendService)
	attributes["backend_service_url"] = record.BackendService
	attributes["service_label"] = record.ServiceLabel
	attributes["service_name"] = record.ServiceName
	attributes["public"] = boolString(external)
	attributes["internet_exposed"] = boolString(external)
	attributes["external_exposure"] = boolString(external)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-forwarding-rule-"+resourceID, "gcp.compute_forwarding_rule", "gcp/compute_forwarding_rule/v1", payload, attributes)
}

func ComputeSubnetworkEvent(settings Settings, record ComputeSubnetworkRecord) (*primitives.Event, error) {
	location := lastPathSegment(record.Region)
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_subnetwork", resourceID, record.Name, "compute_subnetwork", location, record.Labels)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["ip_cidr_range"] = record.IPCIDRRange
	attributes["private_ip_google_access"] = boolString(record.PrivateIPGoogleAccess)
	attributes["purpose"] = record.Purpose
	attributes["role"] = record.Role
	attributes["stack_type"] = record.StackType
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-subnetwork-"+resourceID, "gcp.compute_subnetwork", "gcp/compute_subnetwork/v1", payload, attributes)
}

func ComputeDiskEvent(settings Settings, record ComputeDiskRecord) (*primitives.Event, error) {
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_disk", resourceID, record.Name, "compute_disk", location, record.Labels)
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = firstNonEmpty(lastPathSegment(record.Region), attributes["region"])
	attributes["disk_type"] = lastPathSegment(record.Type)
	attributes["status"] = record.Status
	attributes["size_gb"] = record.SizeGB
	attributes["attached_to"] = strings.Join(record.Users, ",")
	attributes["kms_key_name"] = record.DiskEncryptionKey.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.DiskEncryptionKey.KMSKeyName != "")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-disk-"+resourceID, "gcp.compute_disk", "gcp/compute_disk/v1", payload, attributes)
}

func GKEClusterEvent(settings Settings, record GKEClusterRecord) (*primitives.Event, error) {
	location := firstNonEmpty(record.Location, locationFromResourceName(record.Name))
	serviceAccountEmail := record.NodeConfig.ServiceAccount
	publicEndpoint := record.Endpoint != "" && !record.PrivateClusterConfig.EnablePrivateEndpoint
	attributes := cloudResourceAttributes(settings, "gke_cluster", firstNonEmpty(record.SelfLink, record.Name), record.Name, "gke_cluster", location, record.ResourceLabels)
	attributes["status"] = record.Status
	attributes["version"] = record.CurrentMasterVersion
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["network_tags"] = strings.Join(record.NodeConfig.Tags, ",")
	attributes["security_tags"] = strings.Join(record.NodeConfig.Tags, ",")
	attributes["endpoint"] = record.Endpoint
	attributes["public_endpoint"] = record.Endpoint
	attributes["private_nodes"] = boolString(record.PrivateClusterConfig.EnablePrivateNodes)
	attributes["private_endpoint"] = boolString(record.PrivateClusterConfig.EnablePrivateEndpoint)
	attributes["master_authorized_networks"] = boolString(record.MasterAuthorizedNetworksConfig.Enabled)
	attributes["authorized_cidrs"] = strings.Join(gkeAuthorizedCIDRs(record), ",")
	attributes["public"] = boolString(publicEndpoint)
	attributes["internet_exposed"] = boolString(publicEndpoint)
	attributes["external_exposure"] = boolString(publicEndpoint)
	attributes["kms_key_name"] = record.DatabaseEncryption.KeyName
	attributes["encryption_state"] = record.DatabaseEncryption.State
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-gke-cluster-"+firstNonEmpty(record.SelfLink, record.Name), "gcp.gke_cluster", "gcp/gke_cluster/v1", payload, attributes)
}

func GKENodePoolEvent(settings Settings, record GKENodePoolRecord) (*primitives.Event, error) {
	location := firstNonEmpty(record.ClusterLocation, locationFromResourceName(record.SelfLink), locationFromResourceName(record.Name))
	resourceID := firstNonEmpty(record.SelfLink, record.Name)
	resourceName := lastPathSegment(firstNonEmpty(record.Name, record.SelfLink))
	serviceAccountEmail := record.Config.ServiceAccount
	attributes := cloudResourceAttributes(settings, "gke_node_pool", resourceID, resourceName, "gke_node_pool", location, record.Config.Labels)
	attributes["cluster"] = record.ClusterName
	attributes["cluster_name"] = record.ClusterName
	attributes["status"] = record.Status
	attributes["version"] = record.Version
	attributes["node_locations"] = strings.Join(record.Locations, ",")
	attributes["machine_type"] = record.Config.MachineType
	attributes["disk_type"] = record.Config.DiskType
	attributes["disk_size_gb"] = strconv.Itoa(record.Config.DiskSizeGB)
	attributes["image_type"] = record.Config.ImageType
	attributes["config.image_type"] = record.Config.ImageType
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["network_tags"] = strings.Join(record.Config.Tags, ",")
	attributes["security_tags"] = strings.Join(record.Config.Tags, ",")
	attributes["workload_metadata_mode"] = record.Config.WorkloadMetadataConfig.Mode
	attributes["config.workload_metadata_config.mode"] = record.Config.WorkloadMetadataConfig.Mode
	attributes["secure_boot"] = boolString(record.Config.ShieldedInstanceConfig.EnableSecureBoot)
	attributes["integrity_monitoring"] = boolString(record.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring)
	attributes["auto_repair"] = boolString(record.Management.AutoRepair)
	attributes["auto_upgrade"] = boolString(record.Management.AutoUpgrade)
	attributes["management.auto_repair"] = boolString(record.Management.AutoRepair)
	attributes["management.auto_upgrade"] = boolString(record.Management.AutoUpgrade)
	attributes["autoscaling_enabled"] = boolString(record.Autoscaling.Enabled)
	attributes["autoscaling_min_nodes"] = strconv.Itoa(record.Autoscaling.MinNodeCount)
	attributes["autoscaling_max_nodes"] = strconv.Itoa(record.Autoscaling.MaxNodeCount)
	attributes["initial_node_count"] = strconv.Itoa(record.InitialNodeCount)
	attributes["kms_key_name"] = record.Config.BootDiskKMSCryptoKeyName
	payload, err := payloadWithRaw(record.Raw, map[string]any{"cluster": record.ClusterName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-gke-node-pool-"+resourceID, "gcp.gke_node_pool", "gcp/gke_node_pool/v1", payload, attributes)
}

func gkeAuthorizedCIDRs(record GKEClusterRecord) []string {
	cidrs := make([]string, 0, len(record.MasterAuthorizedNetworksConfig.CidrBlocks))
	for _, block := range record.MasterAuthorizedNetworksConfig.CidrBlocks {
		if cidr := strings.TrimSpace(block.CidrBlock); cidr != "" {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

func computeRouteNextHop(record ComputeRouteRecord) (string, string, string) {
	for _, candidate := range []struct {
		kind string
		url  string
	}{
		{kind: "gateway", url: record.NextHopGateway},
		{kind: "instance", url: record.NextHopInstance},
		{kind: "vpn_gateway", url: record.NextHopVPNGateway},
		{kind: "vpn_tunnel", url: record.NextHopVPNTunnel},
		{kind: "ilb", url: record.NextHopILB},
		{kind: "network", url: record.NextHopNetwork},
		{kind: "peering", url: record.NextHopPeering},
		{kind: "hub", url: record.NextHopHub},
		{kind: "interconnect_attachment", url: record.NextHopInterconnectAttachment},
	} {
		if candidate.url != "" {
			return candidate.kind, candidate.url, lastPathSegment(candidate.url)
		}
	}
	if record.NextHopIP != "" {
		return "ip", record.NextHopIP, record.NextHopIP
	}
	return "", "", ""
}

func firstComputeNetworkInterface(record ComputeInstanceRecord) ComputeNetworkInterface {
	if len(record.NetworkInterfaces) == 0 {
		return ComputeNetworkInterface{}
	}
	return record.NetworkInterfaces[0]
}

func firstComputeServiceAccountEmail(record ComputeInstanceRecord) string {
	for _, account := range record.ServiceAccounts {
		if email := strings.TrimSpace(account.Email); email != "" {
			return email
		}
	}
	return ""
}

func computePublicIP(record ComputeInstanceRecord) string {
	for _, networkInterface := range record.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if ip := strings.TrimSpace(accessConfig.NatIP); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func computeInstanceKMSKey(record ComputeInstanceRecord) string {
	for _, disk := range record.Disks {
		if key := strings.TrimSpace(disk.DiskEncryptionKey.KMSKeyName); key != "" {
			return key
		}
	}
	return ""
}

func computeNamedPorts(ports []ComputeNamedPort) []string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		if port.Name == "" && port.Port == 0 {
			continue
		}
		values = append(values, port.Name+":"+strconv.Itoa(port.Port))
	}
	return values
}

func computeRouterNATs(nats []ComputeRouterNAT) ([]string, []string, []string, bool) {
	names := make([]string, 0, len(nats))
	ips := []string{}
	modes := []string{}
	logging := false
	for _, nat := range nats {
		if nat.Name != "" {
			names = append(names, nat.Name)
		}
		ips = append(ips, nat.NATIPs...)
		if nat.NATIPAllocateOption != "" {
			modes = append(modes, nat.NATIPAllocateOption)
		}
		logging = logging || nat.LogConfig.Enable
	}
	return names, ips, modes, logging
}

func computeRouterInterfaces(interfaces []ComputeRouterIface) []string {
	values := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Name == "" {
			continue
		}
		target := lastPathSegment(firstNonEmpty(iface.LinkedVPNTunnel, iface.LinkedInterconnectAttachment, iface.Subnetwork))
		if target == "" {
			values = append(values, iface.Name)
			continue
		}
		values = append(values, iface.Name+":"+target)
	}
	return values
}

func computeRouterPeers(peers []ComputeRouterBGPPeer) ([]string, []string) {
	names := make([]string, 0, len(peers))
	asns := make([]string, 0, len(peers))
	for _, peer := range peers {
		if peer.Name != "" {
			names = append(names, peer.Name)
		}
		if peer.PeerASN != 0 {
			asns = append(asns, strconv.FormatInt(peer.PeerASN, 10))
		}
	}
	return names, asns
}

func computeVPNGatewayInterfaceIPs(interfaces []ComputeVPNGatewayInterface) []string {
	values := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.IPAddress != "" {
			values = append(values, iface.IPAddress)
		}
	}
	return values
}

func computeExternalVPNGatewayInterfaceIPs(interfaces []ComputeExternalVPNGatewayInterface) ([]string, []string) {
	ipv4 := make([]string, 0, len(interfaces))
	ipv6 := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.IPAddress != "" {
			ipv4 = append(ipv4, iface.IPAddress)
		}
		if iface.IPv6Address != "" {
			ipv6 = append(ipv6, iface.IPv6Address)
		}
	}
	return ipv4, ipv6
}

func computeInterconnectOutages(outages []ComputeInterconnectOutage) []string {
	values := make([]string, 0, len(outages))
	for _, outage := range outages {
		label := firstNonEmpty(outage.Name, outage.IssueType, outage.State)
		if label == "" {
			continue
		}
		if outage.State != "" && outage.State != label {
			label += ":" + outage.State
		}
		values = append(values, label)
	}
	return values
}

type firewallPolicyRuleSummary struct {
	Actions               []string
	Priorities            []string
	SourceRanges          []string
	DestinationRanges     []string
	Layer4Configs         []string
	TargetResources       []string
	TargetServiceAccounts []string
	LoggingEnabled        bool
	DisabledCount         int
}

func computeFirewallPolicyRuleSummary(rules []ComputeFirewallPolicyRule) firewallPolicyRuleSummary {
	var summary firewallPolicyRuleSummary
	for _, rule := range rules {
		if rule.Action != "" {
			summary.Actions = append(summary.Actions, rule.Action)
		}
		if rule.Priority != 0 {
			summary.Priorities = append(summary.Priorities, strconv.Itoa(rule.Priority))
		}
		summary.SourceRanges = append(summary.SourceRanges, rule.Match.SrcIPRanges...)
		summary.DestinationRanges = append(summary.DestinationRanges, rule.Match.DestIPRanges...)
		summary.TargetResources = append(summary.TargetResources, lastPathSegments(rule.TargetResources)...)
		summary.TargetServiceAccounts = append(summary.TargetServiceAccounts, rule.TargetServiceAccounts...)
		summary.Layer4Configs = append(summary.Layer4Configs, computeFirewallPolicyLayer4Configs(rule.Match.Layer4Configs)...)
		summary.LoggingEnabled = summary.LoggingEnabled || rule.EnableLogging
		if rule.Disabled {
			summary.DisabledCount++
		}
	}
	return summary
}

func computeFirewallPolicyLayer4Configs(configs []ComputeFirewallPolicyLayer4Config) []string {
	values := make([]string, 0, len(configs))
	for _, config := range configs {
		if config.IPProtocol == "" {
			continue
		}
		if len(config.Ports) == 0 {
			values = append(values, config.IPProtocol)
			continue
		}
		values = append(values, config.IPProtocol+":"+strings.Join(config.Ports, "|"))
	}
	return values
}

func computeFirewallPolicyAssociations(associations []ComputeFirewallPolicyAssociation) []string {
	values := make([]string, 0, len(associations))
	for _, association := range associations {
		if label := firstNonEmpty(association.DisplayName, association.ShortName, association.Name, lastPathSegment(association.AttachmentTarget)); label != "" {
			values = append(values, label)
		}
	}
	return values
}

func computeAutoHealingHealthChecks(policies []ComputeAutoHealingPolicy) []string {
	values := make([]string, 0, len(policies))
	for _, policy := range policies {
		if policy.HealthCheck != "" {
			values = append(values, policy.HealthCheck)
		}
	}
	return values
}

func firstTemplateNetworkInterface(properties ComputeInstanceTemplateProperties) ComputeNetworkInterface {
	if len(properties.NetworkInterfaces) == 0 {
		return ComputeNetworkInterface{}
	}
	return properties.NetworkInterfaces[0]
}

func computeTemplateServiceAccounts(properties ComputeInstanceTemplateProperties) []string {
	accounts := make([]string, 0, len(properties.ServiceAccounts))
	for _, account := range properties.ServiceAccounts {
		if email := strings.TrimSpace(account.Email); email != "" {
			accounts = append(accounts, email)
		}
	}
	return accounts
}

func computeTemplatePublic(properties ComputeInstanceTemplateProperties) bool {
	for _, networkInterface := range properties.NetworkInterfaces {
		if len(networkInterface.AccessConfigs) != 0 {
			return true
		}
	}
	return false
}

func computeTemplateBootDiskKMS(properties ComputeInstanceTemplateProperties) string {
	for _, disk := range properties.Disks {
		if !disk.Boot {
			continue
		}
		if key := strings.TrimSpace(disk.DiskEncryptionKey.KMSKeyName); key != "" {
			return key
		}
	}
	return ""
}

func computeDistributionZones(policy ComputeInstanceDistribution) []string {
	zones := make([]string, 0, len(policy.Zones))
	for _, zone := range policy.Zones {
		if zone.Zone != "" {
			zones = append(zones, lastPathSegment(zone.Zone))
		}
	}
	return zones
}

func computeBackendServiceExternal(scheme string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(scheme)), "EXTERNAL")
}

func computeBackendServiceBackends(backends []ComputeBackendServiceBackend) ([]string, []string, []string, int) {
	names := make([]string, 0, len(backends))
	urls := make([]string, 0, len(backends))
	modes := make([]string, 0, len(backends))
	failoverCount := 0
	for _, backend := range backends {
		if backend.Group != "" {
			urls = append(urls, backend.Group)
			names = append(names, lastPathSegment(backend.Group))
		}
		if backend.BalancingMode != "" {
			modes = appendUnique(modes, backend.BalancingMode)
		}
		if backend.Failover {
			failoverCount++
		}
	}
	return names, urls, modes, failoverCount
}

func computeAddressExternal(addressType string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(addressType))
	return normalized == "" || normalized == "EXTERNAL"
}

func computeBackendBucketUsedBy(references []ComputeBackendBucketReference) ([]string, []string) {
	names := make([]string, 0, len(references))
	urls := make([]string, 0, len(references))
	for _, usedBy := range references {
		reference := strings.TrimSpace(usedBy.Reference)
		if reference == "" {
			continue
		}
		urls = append(urls, reference)
		names = append(names, lastPathSegment(reference))
	}
	return names, urls
}

func computeBackendBucketNegativeCachingCodes(policies []ComputeBackendBucketNegativeCachingEntry) []string {
	codes := make([]string, 0, len(policies))
	for _, policy := range policies {
		if policy.Code != 0 {
			codes = append(codes, strconv.Itoa(policy.Code))
		}
	}
	sort.Strings(codes)
	return codes
}

func computeHealthCheckProbe(record ComputeHealthCheckRecord) (string, ComputeHealthCheckProbe) {
	switch strings.ToUpper(strings.TrimSpace(record.Type)) {
	case "TCP":
		return "TCP", record.TCPHealthCheck
	case "SSL":
		return "SSL", record.SSLHealthCheck
	case "HTTP":
		return "HTTP", record.HTTPHealthCheck
	case "HTTPS":
		return "HTTPS", record.HTTPSHealthCheck
	case "HTTP2":
		return "HTTP2", record.HTTP2HealthCheck
	case "GRPC":
		return "GRPC", record.GRPCHealthCheck
	case "GRPC_TLS":
		return "GRPC_TLS", record.GRPCTLSHealthCheck
	}
	switch {
	case computeHealthCheckProbeConfigured(record.TCPHealthCheck):
		return "TCP", record.TCPHealthCheck
	case computeHealthCheckProbeConfigured(record.SSLHealthCheck):
		return "SSL", record.SSLHealthCheck
	case computeHealthCheckProbeConfigured(record.HTTPHealthCheck):
		return "HTTP", record.HTTPHealthCheck
	case computeHealthCheckProbeConfigured(record.HTTPSHealthCheck):
		return "HTTPS", record.HTTPSHealthCheck
	case computeHealthCheckProbeConfigured(record.HTTP2HealthCheck):
		return "HTTP2", record.HTTP2HealthCheck
	case computeHealthCheckProbeConfigured(record.GRPCHealthCheck):
		return "GRPC", record.GRPCHealthCheck
	case computeHealthCheckProbeConfigured(record.GRPCTLSHealthCheck):
		return "GRPC_TLS", record.GRPCTLSHealthCheck
	default:
		return record.Type, ComputeHealthCheckProbe{}
	}
}

func computeHealthCheckProbeConfigured(probe ComputeHealthCheckProbe) bool {
	return probe.Port != 0 || probe.PortName != "" || probe.PortSpecification != "" || probe.Request != "" || probe.Response != "" || probe.ProxyHeader != "" || probe.Host != "" || probe.RequestPath != "" || probe.GRPCServiceName != ""
}

type computeSecurityPolicyRuleSummary struct {
	actions               []string
	versionedExpressions  []string
	sourceIPRanges        []string
	customExpressions     []string
	defaultAction         string
	previewCount          int
	allowCount            int
	denyCount             int
	throttleCount         int
	rateBasedBanCount     int
	redirectCount         int
	customExpressionCount int
}

func computeSecurityPolicyRules(rules []ComputeSecurityPolicyRule) computeSecurityPolicyRuleSummary {
	summary := computeSecurityPolicyRuleSummary{}
	defaultPriority := -1
	for _, rule := range rules {
		action := strings.TrimSpace(rule.Action)
		normalizedAction := strings.ToLower(action)
		if action != "" {
			summary.actions = appendUnique(summary.actions, action)
		}
		switch {
		case normalizedAction == "allow":
			summary.allowCount++
		case strings.HasPrefix(normalizedAction, "deny"):
			summary.denyCount++
		case strings.HasPrefix(normalizedAction, "throttle"):
			summary.throttleCount++
		case strings.HasPrefix(normalizedAction, "rate_based_ban"):
			summary.rateBasedBanCount++
		case strings.HasPrefix(normalizedAction, "redirect"):
			summary.redirectCount++
		}
		if rule.Preview {
			summary.previewCount++
		}
		if rule.Priority > defaultPriority {
			defaultPriority = rule.Priority
			summary.defaultAction = action
		}
		if versionedExpression := strings.TrimSpace(rule.Match.VersionedExpr); versionedExpression != "" {
			summary.versionedExpressions = appendUnique(summary.versionedExpressions, versionedExpression)
		}
		for _, sourceIPRange := range rule.Match.Config.SrcIPRanges {
			if sourceIPRange = strings.TrimSpace(sourceIPRange); sourceIPRange != "" {
				summary.sourceIPRanges = appendUnique(summary.sourceIPRanges, sourceIPRange)
			}
		}
		if expression := strings.TrimSpace(rule.Match.Expr.Expression); expression != "" {
			summary.customExpressions = append(summary.customExpressions, expression)
			summary.customExpressionCount++
		}
	}
	return summary
}

func computeSecurityPolicyAssociations(associations []ComputeSecurityPolicyAssociation) ([]string, []string) {
	names := make([]string, 0, len(associations))
	urls := make([]string, 0, len(associations))
	for _, association := range associations {
		if association.AttachmentID != "" {
			urls = append(urls, association.AttachmentID)
			names = append(names, firstNonEmpty(association.Name, lastPathSegment(association.AttachmentID)))
			continue
		}
		if association.Name != "" {
			names = append(names, association.Name)
		}
	}
	return names, urls
}

type computeURLMapRouteSummary struct {
	hosts                        []string
	pathMatchers                 []string
	paths                        []string
	backendNames                 []string
	backendURLs                  []string
	pathRulesCount               int
	routeRulesCount              int
	redirectRulesCount           int
	weightedBackendServicesCount int
}

func computeURLMapRoutes(record ComputeURLMapRecord) computeURLMapRouteSummary {
	summary := computeURLMapRouteSummary{}
	addURLMapBackend(&summary, record.DefaultService)
	addURLMapWeightedBackends(&summary, record.DefaultRouteAction)
	if computeURLRedirectConfigured(record.DefaultURLRedirect) {
		summary.redirectRulesCount++
	}
	for _, hostRule := range record.HostRules {
		for _, host := range hostRule.Hosts {
			summary.hosts = appendUnique(summary.hosts, host)
		}
		if hostRule.PathMatcher != "" {
			summary.pathMatchers = appendUnique(summary.pathMatchers, hostRule.PathMatcher)
		}
	}
	for _, matcher := range record.PathMatchers {
		if matcher.Name != "" {
			summary.pathMatchers = appendUnique(summary.pathMatchers, matcher.Name)
		}
		addURLMapBackend(&summary, matcher.DefaultService)
		addURLMapWeightedBackends(&summary, matcher.DefaultRouteAction)
		if computeURLRedirectConfigured(matcher.DefaultURLRedirect) {
			summary.redirectRulesCount++
		}
		for _, rule := range matcher.PathRules {
			summary.pathRulesCount++
			for _, path := range rule.Paths {
				summary.paths = appendUnique(summary.paths, path)
			}
			addURLMapBackend(&summary, rule.Service)
			addURLMapWeightedBackends(&summary, rule.RouteAction)
			if computeURLRedirectConfigured(rule.URLRedirect) {
				summary.redirectRulesCount++
			}
		}
		for _, rule := range matcher.RouteRules {
			summary.routeRulesCount++
			addURLMapBackend(&summary, rule.Service)
			addURLMapWeightedBackends(&summary, rule.RouteAction)
			if computeURLRedirectConfigured(rule.URLRedirect) {
				summary.redirectRulesCount++
			}
		}
	}
	return summary
}

func addURLMapBackend(summary *computeURLMapRouteSummary, backend string) {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return
	}
	summary.backendURLs = appendUnique(summary.backendURLs, backend)
	summary.backendNames = appendUnique(summary.backendNames, lastPathSegment(backend))
}

func addURLMapWeightedBackends(summary *computeURLMapRouteSummary, action ComputeURLMapRouteAction) {
	for _, backend := range action.WeightedBackendServices {
		addURLMapBackend(summary, backend.BackendService)
		summary.weightedBackendServicesCount++
	}
}

func computeURLRedirectConfigured(redirect ComputeURLMapURLRedirect) bool {
	return redirect.HostRedirect != "" || redirect.PathRedirect != "" || redirect.PrefixRedirect != "" || redirect.RedirectResponseCode != "" || redirect.HTTPSRedirect || redirect.StripQuery
}

func computeSSLCertificateType(record ComputeSSLCertificateRecord) string {
	switch {
	case len(record.Managed.Domains) != 0 || record.Managed.Status != "" || len(record.Managed.DomainStatus) != 0:
		return "MANAGED"
	case record.SelfManaged.Certificate != "":
		return "SELF_MANAGED"
	default:
		return ""
	}
}

func computeSSLCertificateDomainStatuses(statuses map[string]string) []string {
	if len(statuses) == 0 {
		return nil
	}
	domains := make([]string, 0, len(statuses))
	for domain := range statuses {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	values := make([]string, 0, len(domains))
	for _, domain := range domains {
		values = append(values, domain+"="+statuses[domain])
	}
	return values
}

func lastPathSegments(values []string) []string {
	segments := make([]string, 0, len(values))
	for _, value := range values {
		if segment := lastPathSegment(value); segment != "" {
			segments = append(segments, segment)
		}
	}
	return segments
}

func computeForwardingRuleTarget(record ComputeForwardingRuleRecord) (string, string, string) {
	if record.BackendService != "" {
		return "backend_service", record.BackendService, lastPathSegment(record.BackendService)
	}
	if record.Target != "" {
		return computeForwardingRuleTargetType(record.Target), record.Target, lastPathSegment(record.Target)
	}
	return "", "", ""
}

func computeForwardingRuleTargetType(targetURL string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(targetURL), "/"), "/")
	if len(parts) < 2 {
		return "target"
	}
	switch parts[len(parts)-2] {
	case "backendServices":
		return "backend_service"
	case "serviceAttachments":
		return "service_attachment"
	case "targetGrpcProxies":
		return "target_grpc_proxy"
	case "targetHttpProxies":
		return "target_http_proxy"
	case "targetHttpsProxies":
		return "target_https_proxy"
	case "targetInstances":
		return "target_instance"
	case "targetPools":
		return "target_pool"
	case "targetSslProxies":
		return "target_ssl_proxy"
	case "targetTcpProxies":
		return "target_tcp_proxy"
	case "targetVpnGateways":
		return "target_vpn_gateway"
	}
	return "target"
}

func computeForwardingRuleExternal(scheme string) bool {
	upper := strings.ToUpper(strings.TrimSpace(scheme))
	return strings.HasPrefix(upper, "EXTERNAL")
}

func computeFirewallPrimaryAllowed(record ComputeFirewallRecord) ComputeFirewallAllowed {
	if len(record.Allowed) == 0 {
		return ComputeFirewallAllowed{IPProtocol: "all"}
	}
	allowed := record.Allowed[0]
	if len(allowed.Ports) == 0 {
		allowed.Ports = []string{"all"}
	}
	return allowed
}

func cloudRunImages(record CloudRunServiceRecord) []string {
	images := make([]string, 0, len(record.Template.Containers))
	for _, container := range record.Template.Containers {
		if strings.TrimSpace(container.Image) != "" {
			images = append(images, container.Image)
		}
	}
	return images
}

func cloudRunAllowsAllIngress(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	return normalized == "INGRESS_TRAFFIC_ALL" || normalized == "ALLOW_ALL" || normalized == "ALL"
}
