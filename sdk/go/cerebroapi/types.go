package cerebroapi

type SourceRuntime struct {
	ID       string            `json:"id,omitempty"`
	SourceID string            `json:"source_id"`
	TenantID string            `json:"tenant_id"`
	Config   map[string]string `json:"config,omitempty"`
}

type EntityRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

type Claim struct {
	ID            string            `json:"id,omitempty"`
	SubjectURN    string            `json:"subject_urn"`
	SubjectRef    EntityRef         `json:"subject_ref"`
	Predicate     string            `json:"predicate"`
	ObjectURN     string            `json:"object_urn,omitempty"`
	ObjectRef     *EntityRef        `json:"object_ref,omitempty"`
	ObjectValue   string            `json:"object_value,omitempty"`
	ClaimType     string            `json:"claim_type"`
	Status        string            `json:"status"`
	SourceEventID string            `json:"source_event_id,omitempty"`
	ObservedAt    string            `json:"observed_at,omitempty"`
	ValidFrom     string            `json:"valid_from,omitempty"`
	ValidTo       string            `json:"valid_to,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

type ListClaimsRequest struct {
	RuntimeID     string
	ClaimID       string
	SubjectURN    string
	Predicate     string
	ObjectURN     string
	ObjectValue   string
	ClaimType     string
	Status        string
	SourceEventID string
	Limit         uint32
}

type ListClaimsResponse struct {
	Claims []Claim `json:"claims"`
}

type WriteClaimsRequest struct {
	RuntimeID       string  `json:"runtime_id"`
	Claims          []Claim `json:"claims"`
	ReplaceExisting bool    `json:"replace_existing,omitempty"`
}

type WriteClaimsResponse struct {
	ClaimsWritten          uint32 `json:"claims_written"`
	EntitiesUpserted       uint32 `json:"entities_upserted"`
	RelationLinksProjected uint32 `json:"relation_links_projected"`
	ClaimsRetracted        uint32 `json:"claims_retracted"`
}

type sourceRuntimeResponse struct {
	Runtime *SourceRuntime `json:"runtime"`
}

type GraphEntity struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

type GraphRelation struct {
	FromURN  string `json:"from_urn"`
	Relation string `json:"relation"`
	ToURN    string `json:"to_urn"`
}

type EntityNeighborhood struct {
	Root      *GraphEntity    `json:"root,omitempty"`
	Neighbors []GraphEntity   `json:"neighbors,omitempty"`
	Relations []GraphRelation `json:"relations,omitempty"`
}
