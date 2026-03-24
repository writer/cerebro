package graph

import "strings"

const (
	commonPropertyKeyServiceID          = "service_id"
	commonPropertyKeyPublicIP           = "public_ip"
	commonPropertyKeyDataClassification = "data_classification"
	commonPropertyKeyIdentityType       = "identity_type"
	commonPropertyKeyInternetExposed    = "internet_exposed"
	commonPropertyKeyMFAEnabled         = "mfa_enabled"
	commonPropertyKeyContainsPII        = "contains_pii"
	commonPropertyKeyContainsPHI        = "contains_phi"
	commonPropertyKeyContainsPCI        = "contains_pci"
	commonPropertyKeyContainsSecrets    = "contains_secrets"
)

type commonPropertyPresence uint16

const (
	commonPropertyServiceID commonPropertyPresence = 1 << iota
	commonPropertyPublicIP
	commonPropertyDataClassification
	commonPropertyIdentityType
	commonPropertyInternetExposed
	commonPropertyMFAEnabled
	commonPropertyContainsPII
	commonPropertyContainsPHI
	commonPropertyContainsPCI
	commonPropertyContainsSecrets
)

// NodeCommonProperties captures stable, high-frequency scalar node properties
// that are widely queried across risk, graph, and reporting paths.
type NodeCommonProperties struct {
	ServiceID          string
	PublicIP           string
	DataClassification string
	IdentityType       string
	InternetExposed    bool
	MFAEnabled         bool
	ContainsPII        bool
	ContainsPHI        bool
	ContainsPCI        bool
	ContainsSecrets    bool
	present            commonPropertyPresence
}

func (n *Node) CommonProperties() (NodeCommonProperties, bool) {
	if n == nil {
		return NodeCommonProperties{}, false
	}
	if n.propertyColumns != nil && n.ordinal != InvalidNodeOrdinal {
		if props, ok := n.propertyColumns.CommonProperties(n.ordinal); ok {
			return props, true
		}
	}
	if n.commonProps != nil {
		return cloneNodeCommonProperties(*n.commonProps), true
	}
	return commonNodePropertiesFromMap(n.Properties)
}

func (n *Node) PropertyString(key string) string {
	if n == nil {
		return ""
	}
	value, ok := n.PropertyValue(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(observationStringValue(value))
}

func (n *Node) PropertyBool(key string) (bool, bool) {
	if n == nil {
		return false, false
	}
	value, ok := n.PropertyValue(key)
	if !ok {
		return false, false
	}
	return commonBoolValue(value)
}

func cloneNodeCommonProperties(props NodeCommonProperties) NodeCommonProperties {
	return props
}

func ptrNodeCommonProperties(props NodeCommonProperties) *NodeCommonProperties {
	cloned := cloneNodeCommonProperties(props)
	return &cloned
}

func commonNodePropertiesFromMap(properties map[string]any) (NodeCommonProperties, bool) {
	if len(properties) == 0 {
		return NodeCommonProperties{}, false
	}

	var props NodeCommonProperties
	if value, ok := properties[commonPropertyKeyServiceID]; ok && value != nil {
		props.ServiceID = strings.TrimSpace(observationStringValue(value))
		props.present |= commonPropertyServiceID
	}
	if value, ok := properties[commonPropertyKeyPublicIP]; ok && value != nil {
		props.PublicIP = strings.TrimSpace(observationStringValue(value))
		props.present |= commonPropertyPublicIP
	}
	if value, ok := properties[commonPropertyKeyDataClassification]; ok && value != nil {
		props.DataClassification = strings.TrimSpace(observationStringValue(value))
		props.present |= commonPropertyDataClassification
	}
	if value, ok := properties[commonPropertyKeyIdentityType]; ok && value != nil {
		props.IdentityType = strings.TrimSpace(observationStringValue(value))
		props.present |= commonPropertyIdentityType
	}
	if value, ok := properties[commonPropertyKeyInternetExposed]; ok && value != nil {
		if parsed, ok := commonBoolValue(value); ok {
			props.InternetExposed = parsed
			props.present |= commonPropertyInternetExposed
		}
	}
	if value, ok := properties[commonPropertyKeyMFAEnabled]; ok && value != nil {
		if parsed, ok := commonBoolValue(value); ok {
			props.MFAEnabled = parsed
			props.present |= commonPropertyMFAEnabled
		}
	}
	if value, ok := properties[commonPropertyKeyContainsPII]; ok && value != nil {
		if parsed, ok := commonBoolValue(value); ok {
			props.ContainsPII = parsed
			props.present |= commonPropertyContainsPII
		}
	}
	if value, ok := properties[commonPropertyKeyContainsPHI]; ok && value != nil {
		if parsed, ok := commonBoolValue(value); ok {
			props.ContainsPHI = parsed
			props.present |= commonPropertyContainsPHI
		}
	}
	if value, ok := properties[commonPropertyKeyContainsPCI]; ok && value != nil {
		if parsed, ok := commonBoolValue(value); ok {
			props.ContainsPCI = parsed
			props.present |= commonPropertyContainsPCI
		}
	}
	if value, ok := properties[commonPropertyKeyContainsSecrets]; ok && value != nil {
		if parsed, ok := commonBoolValue(value); ok {
			props.ContainsSecrets = parsed
			props.present |= commonPropertyContainsSecrets
		}
	}
	if props.present == 0 {
		return NodeCommonProperties{}, false
	}
	return props, true
}

func commonPropertyValue(props NodeCommonProperties, key string) (any, bool) {
	switch strings.TrimSpace(key) {
	case commonPropertyKeyServiceID:
		if props.present&commonPropertyServiceID == 0 {
			return nil, false
		}
		return props.ServiceID, true
	case commonPropertyKeyPublicIP:
		if props.present&commonPropertyPublicIP == 0 {
			return nil, false
		}
		return props.PublicIP, true
	case commonPropertyKeyDataClassification:
		if props.present&commonPropertyDataClassification == 0 {
			return nil, false
		}
		return props.DataClassification, true
	case commonPropertyKeyIdentityType:
		if props.present&commonPropertyIdentityType == 0 {
			return nil, false
		}
		return props.IdentityType, true
	case commonPropertyKeyInternetExposed:
		if props.present&commonPropertyInternetExposed == 0 {
			return nil, false
		}
		return props.InternetExposed, true
	case commonPropertyKeyMFAEnabled:
		if props.present&commonPropertyMFAEnabled == 0 {
			return nil, false
		}
		return props.MFAEnabled, true
	case commonPropertyKeyContainsPII:
		if props.present&commonPropertyContainsPII == 0 {
			return nil, false
		}
		return props.ContainsPII, true
	case commonPropertyKeyContainsPHI:
		if props.present&commonPropertyContainsPHI == 0 {
			return nil, false
		}
		return props.ContainsPHI, true
	case commonPropertyKeyContainsPCI:
		if props.present&commonPropertyContainsPCI == 0 {
			return nil, false
		}
		return props.ContainsPCI, true
	case commonPropertyKeyContainsSecrets:
		if props.present&commonPropertyContainsSecrets == 0 {
			return nil, false
		}
		return props.ContainsSecrets, true
	default:
		return nil, false
	}
}

func setNodeCommonPropertyValue(node *Node, key string, value any) bool {
	if node == nil {
		return false
	}
	props, _ := node.CommonProperties()
	switch strings.TrimSpace(key) {
	case commonPropertyKeyServiceID:
		if value == nil {
			props.ServiceID = ""
			props.present &^= commonPropertyServiceID
		} else {
			props.ServiceID = strings.TrimSpace(observationStringValue(value))
			props.present |= commonPropertyServiceID
		}
	case commonPropertyKeyPublicIP:
		if value == nil {
			props.PublicIP = ""
			props.present &^= commonPropertyPublicIP
		} else {
			props.PublicIP = strings.TrimSpace(observationStringValue(value))
			props.present |= commonPropertyPublicIP
		}
	case commonPropertyKeyDataClassification:
		if value == nil {
			props.DataClassification = ""
			props.present &^= commonPropertyDataClassification
		} else {
			props.DataClassification = strings.TrimSpace(observationStringValue(value))
			props.present |= commonPropertyDataClassification
		}
	case commonPropertyKeyIdentityType:
		if value == nil {
			props.IdentityType = ""
			props.present &^= commonPropertyIdentityType
		} else {
			props.IdentityType = strings.TrimSpace(observationStringValue(value))
			props.present |= commonPropertyIdentityType
		}
	case commonPropertyKeyInternetExposed:
		if value == nil {
			props.InternetExposed = false
			props.present &^= commonPropertyInternetExposed
		} else if parsed, ok := commonBoolValue(value); ok {
			props.InternetExposed = parsed
			props.present |= commonPropertyInternetExposed
		} else {
			return false
		}
	case commonPropertyKeyMFAEnabled:
		if value == nil {
			props.MFAEnabled = false
			props.present &^= commonPropertyMFAEnabled
		} else if parsed, ok := commonBoolValue(value); ok {
			props.MFAEnabled = parsed
			props.present |= commonPropertyMFAEnabled
		} else {
			return false
		}
	case commonPropertyKeyContainsPII:
		if value == nil {
			props.ContainsPII = false
			props.present &^= commonPropertyContainsPII
		} else if parsed, ok := commonBoolValue(value); ok {
			props.ContainsPII = parsed
			props.present |= commonPropertyContainsPII
		} else {
			return false
		}
	case commonPropertyKeyContainsPHI:
		if value == nil {
			props.ContainsPHI = false
			props.present &^= commonPropertyContainsPHI
		} else if parsed, ok := commonBoolValue(value); ok {
			props.ContainsPHI = parsed
			props.present |= commonPropertyContainsPHI
		} else {
			return false
		}
	case commonPropertyKeyContainsPCI:
		if value == nil {
			props.ContainsPCI = false
			props.present &^= commonPropertyContainsPCI
		} else if parsed, ok := commonBoolValue(value); ok {
			props.ContainsPCI = parsed
			props.present |= commonPropertyContainsPCI
		} else {
			return false
		}
	case commonPropertyKeyContainsSecrets:
		if value == nil {
			props.ContainsSecrets = false
			props.present &^= commonPropertyContainsSecrets
		} else if parsed, ok := commonBoolValue(value); ok {
			props.ContainsSecrets = parsed
			props.present |= commonPropertyContainsSecrets
		} else {
			return false
		}
	default:
		return false
	}
	applyNodeCommonProperties(node, props)
	return true
}

func applyNodeCommonProperties(node *Node, props NodeCommonProperties) {
	if node == nil {
		return
	}
	if node.propertyColumns != nil && node.ordinal != InvalidNodeOrdinal {
		node.propertyColumns.ClearCommonProperties(node.ordinal)
		if props.present != 0 {
			node.propertyColumns.SetCommonProperties(node.ordinal, props)
		}
		node.commonProps = nil
	} else {
		if props.present == 0 {
			node.commonProps = nil
		} else {
			node.commonProps = ptrNodeCommonProperties(props)
		}
	}
	if node.Properties != nil {
		stripCommonPropertyKeys(node.Properties)
		if len(node.Properties) == 0 {
			node.Properties = nil
		}
	}
}

func bindableNodeCommonProperties(node *Node) (NodeCommonProperties, bool) {
	if node == nil {
		return NodeCommonProperties{}, false
	}
	if node.commonProps != nil {
		return cloneNodeCommonProperties(*node.commonProps), true
	}
	if props, ok := commonNodePropertiesFromMap(node.Properties); ok {
		return props, true
	}
	if node.propertyColumns != nil && node.ordinal != InvalidNodeOrdinal {
		if props, ok := node.propertyColumns.CommonProperties(node.ordinal); ok {
			return props, true
		}
	}
	return NodeCommonProperties{}, false
}

func stripCommonPropertyKeys(properties map[string]any) {
	delete(properties, commonPropertyKeyServiceID)
	delete(properties, commonPropertyKeyPublicIP)
	delete(properties, commonPropertyKeyDataClassification)
	delete(properties, commonPropertyKeyIdentityType)
	delete(properties, commonPropertyKeyInternetExposed)
	delete(properties, commonPropertyKeyMFAEnabled)
	delete(properties, commonPropertyKeyContainsPII)
	delete(properties, commonPropertyKeyContainsPHI)
	delete(properties, commonPropertyKeyContainsPCI)
	delete(properties, commonPropertyKeyContainsSecrets)
}

func materializeCommonProperties(properties map[string]any, props NodeCommonProperties) {
	if props.present&commonPropertyServiceID != 0 {
		properties[commonPropertyKeyServiceID] = props.ServiceID
	}
	if props.present&commonPropertyPublicIP != 0 {
		properties[commonPropertyKeyPublicIP] = props.PublicIP
	}
	if props.present&commonPropertyDataClassification != 0 {
		properties[commonPropertyKeyDataClassification] = props.DataClassification
	}
	if props.present&commonPropertyIdentityType != 0 {
		properties[commonPropertyKeyIdentityType] = props.IdentityType
	}
	if props.present&commonPropertyInternetExposed != 0 {
		properties[commonPropertyKeyInternetExposed] = props.InternetExposed
	}
	if props.present&commonPropertyMFAEnabled != 0 {
		properties[commonPropertyKeyMFAEnabled] = props.MFAEnabled
	}
	if props.present&commonPropertyContainsPII != 0 {
		properties[commonPropertyKeyContainsPII] = props.ContainsPII
	}
	if props.present&commonPropertyContainsPHI != 0 {
		properties[commonPropertyKeyContainsPHI] = props.ContainsPHI
	}
	if props.present&commonPropertyContainsPCI != 0 {
		properties[commonPropertyKeyContainsPCI] = props.ContainsPCI
	}
	if props.present&commonPropertyContainsSecrets != 0 {
		properties[commonPropertyKeyContainsSecrets] = props.ContainsSecrets
	}
}

func commonBoolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes", "y":
			return true, true
		case "false", "0", "no", "n":
			return false, true
		default:
			return false, false
		}
	case int:
		return typed != 0, true
	case int8:
		return typed != 0, true
	case int16:
		return typed != 0, true
	case int32:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case uint:
		return typed != 0, true
	case uint8:
		return typed != 0, true
	case uint16:
		return typed != 0, true
	case uint32:
		return typed != 0, true
	case uint64:
		return typed != 0, true
	case float32:
		return typed != 0, true
	case float64:
		return typed != 0, true
	default:
		return false, false
	}
}
