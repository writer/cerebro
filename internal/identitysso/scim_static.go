package identitysso

// SCIMSupported is a SCIM "supported" flag object.
type SCIMSupported struct {
	Supported bool `json:"supported"`
}

// SCIMFilterSupport describes filter support.
type SCIMFilterSupport struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// SCIMBulkSupport describes bulk support.
type SCIMBulkSupport struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// SCIMAuthScheme describes one supported authentication scheme.
type SCIMAuthScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Primary     bool   `json:"primary"`
}

// SCIMServiceProviderConfig is the ServiceProviderConfig resource.
type SCIMServiceProviderConfig struct {
	Schemas               []string          `json:"schemas"`
	Patch                 SCIMSupported     `json:"patch"`
	Bulk                  SCIMBulkSupport   `json:"bulk"`
	Filter                SCIMFilterSupport `json:"filter"`
	ChangePassword        SCIMSupported     `json:"changePassword"`
	Sort                  SCIMSupported     `json:"sort"`
	ETag                  SCIMSupported     `json:"etag"`
	AuthenticationSchemes []SCIMAuthScheme  `json:"authenticationSchemes"`
}

// SCIMResourceType is one ResourceType resource.
type SCIMResourceType struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	Schema   string   `json:"schema"`
}

// SCIMSchemaAttribute describes one schema attribute.
type SCIMSchemaAttribute struct {
	Name          string                `json:"name"`
	Type          string                `json:"type"`
	MultiValued   bool                  `json:"multiValued"`
	Required      bool                  `json:"required"`
	CaseExact     bool                  `json:"caseExact"`
	Mutability    string                `json:"mutability"`
	Returned      string                `json:"returned"`
	Uniqueness    string                `json:"uniqueness"`
	SubAttributes []SCIMSchemaAttribute `json:"subAttributes,omitempty"`
}

// SCIMSchemaDefinition is one Schema resource.
type SCIMSchemaDefinition struct {
	Schemas     []string              `json:"schemas"`
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Attributes  []SCIMSchemaAttribute `json:"attributes"`
}

// ServiceProviderConfig returns the static SCIM capability document.
func ServiceProviderConfig() SCIMServiceProviderConfig {
	return SCIMServiceProviderConfig{
		Schemas:        []string{SCIMSchemaSPConfig},
		Patch:          SCIMSupported{Supported: true},
		Bulk:           SCIMBulkSupport{},
		Filter:         SCIMFilterSupport{Supported: true, MaxResults: SCIMMaxCount},
		ChangePassword: SCIMSupported{},
		Sort:           SCIMSupported{},
		ETag:           SCIMSupported{},
		AuthenticationSchemes: []SCIMAuthScheme{{
			Type:        "oauthbearertoken",
			Name:        "OAuth Bearer Token",
			Description: "Authentication with a Cerebro SCIM bearer token.",
			Primary:     true,
		}},
	}
}

// ResourceTypes returns the static SCIM resource type list.
func ResourceTypes() []SCIMResourceType {
	return []SCIMResourceType{
		{Schemas: []string{SCIMSchemaResourceType}, ID: "User", Name: "User", Endpoint: "/Users", Schema: SCIMSchemaUser},
		{Schemas: []string{SCIMSchemaResourceType}, ID: "Group", Name: "Group", Endpoint: "/Groups", Schema: SCIMSchemaGroup},
	}
}

func scimAttribute(name string, attrType string, required bool, uniqueness string) SCIMSchemaAttribute {
	return SCIMSchemaAttribute{Name: name, Type: attrType, Required: required, Mutability: "readWrite", Returned: "default", Uniqueness: uniqueness}
}

// Schemas returns the static SCIM schema definitions for the supported attributes.
func Schemas() []SCIMSchemaDefinition {
	userName := scimAttribute("userName", "string", true, "server")
	nameAttr := scimAttribute("name", "complex", false, "none")
	nameAttr.SubAttributes = []SCIMSchemaAttribute{
		scimAttribute("givenName", "string", false, "none"),
		scimAttribute("familyName", "string", false, "none"),
		scimAttribute("formatted", "string", false, "none"),
	}
	emails := scimAttribute("emails", "complex", false, "none")
	emails.MultiValued = true
	emails.SubAttributes = []SCIMSchemaAttribute{
		scimAttribute("value", "string", false, "none"),
		scimAttribute("type", "string", false, "none"),
		scimAttribute("primary", "boolean", false, "none"),
	}
	userGroups := scimAttribute("groups", "complex", false, "none")
	userGroups.MultiValued = true
	userGroups.Mutability = "readOnly"
	members := scimAttribute("members", "complex", false, "none")
	members.MultiValued = true
	members.SubAttributes = []SCIMSchemaAttribute{scimAttribute("value", "string", false, "none")}
	return []SCIMSchemaDefinition{
		{
			Schemas:     []string{SCIMSchemaSchema},
			ID:          SCIMSchemaUser,
			Name:        "User",
			Description: "Cerebro console user",
			Attributes: []SCIMSchemaAttribute{
				userName,
				nameAttr,
				scimAttribute("displayName", "string", false, "none"),
				emails,
				scimAttribute("active", "boolean", false, "none"),
				scimAttribute("externalId", "string", false, "none"),
				userGroups,
			},
		},
		{
			Schemas:     []string{SCIMSchemaSchema},
			ID:          SCIMSchemaGroup,
			Name:        "Group",
			Description: "Cerebro console group",
			Attributes: []SCIMSchemaAttribute{
				scimAttribute("displayName", "string", true, "server"),
				scimAttribute("externalId", "string", false, "none"),
				members,
			},
		},
	}
}
