package azure

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/azurearm"
)

type nsgRecord struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Location   string        `json:"location"`
	Type       string        `json:"type"`
	Properties nsgProperties `json:"properties"`
	raw        json.RawMessage
}

type nsgProperties struct {
	SecurityRules        []nsgRule `json:"securityRules"`
	DefaultSecurityRules []nsgRule `json:"defaultSecurityRules"`
}

type nsgRule struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Properties nsgRuleProperties `json:"properties"`
}

type nsgRuleProperties struct {
	Access                   string `json:"access"`
	Direction                string `json:"direction"`
	Protocol                 string `json:"protocol"`
	SourceAddressPrefix      string `json:"sourceAddressPrefix"`
	SourcePortRange          string `json:"sourcePortRange"`
	DestinationPortRange     string `json:"destinationPortRange"`
	DestinationAddressPrefix string `json:"destinationAddressPrefix"`
	Priority                 int    `json:"priority"`
}

type azureResourceExposure struct {
	NetworkSecurityGroup nsgRecord
	Rule                 nsgRule
}

func listVirtualNetworks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Network/virtualNetworks", "2023-09-01", "azure virtual network")
}

func listSubnets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	virtualNetworks, next, err := listVirtualNetworks(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	rawRecords, err := azurearm.SubnetRecords(virtualNetworks, func(network armTypedResourceRecord) string { return network.ID }, func(network armTypedResourceRecord) string { return network.Location }, func(network armTypedResourceRecord) []any {
		return propertyArray(network, "subnets")
	})
	if err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(rawRecords, "azure subnet", func(record *armTypedResourceRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, next, err
}

func listNetworkSecurityGroups(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Network/networkSecurityGroups", "2023-09-01", "azure network security group")
}

func listPublicIPAddresses(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Network/publicIPAddresses", "2023-09-01", "azure public ip address")
}

func virtualNetworkEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyVirtualNetwork)
	setAttributes(attributes, map[string]string{"address_prefixes": strings.Join(propertyStringSlice(record, "addressSpace", "addressPrefixes"), ","), "subnet_ids": strings.Join(azureChildResourceIDs(record, "subnets"), ","), "subnet_names": strings.Join(azureChildResourceNames(record, "subnets"), ","), "enable_ddos_protection": propertyBoolString(record, "enableDdosProtection")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyVirtualNetwork, record), "azure.virtual_network", "azure/virtual_network/v1", payload, attributes, time.Now().UTC())
}

func networkSecurityGroupEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyNetworkSecurityGrp)
	setAttributes(attributes, map[string]string{"security_rule_names": strings.Join(azureChildResourceNames(record, "securityRules"), ","), "default_security_rule_names": strings.Join(azureChildResourceNames(record, "defaultSecurityRules"), ","), "network_interface_ids": strings.Join(azureChildResourceIDs(record, "networkInterfaces"), ","), "subnet_ids": strings.Join(azureChildResourceIDs(record, "subnets"), ",")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyNetworkSecurityGrp, record), "azure.network_security_group", "azure/network_security_group/v1", payload, attributes, time.Now().UTC())
}

func publicIPAddressEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyPublicIPAddress)
	hosts := azurePublicIPHosts(record)
	setAttributes(attributes, map[string]string{"ip_address": propertyString(record, "ipAddress"), "public_host": strings.Join(hosts, ","), "public_ip_allocation_method": propertyString(record, "publicIPAllocationMethod"), "public_ip_address_version": propertyString(record, "publicIPAddressVersion"), "idle_timeout_minutes": propertyString(record, "idleTimeoutInMinutes"), "internet_exposed": boolString(len(hosts) > 0 || propertyString(record, "ipAddress") != "")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyPublicIPAddress, record), "azure.public_ip_address", "azure/public_ip_address/v1", payload, attributes, time.Now().UTC())
}
