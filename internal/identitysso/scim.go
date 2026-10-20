package identitysso

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// SCIM schema URNs (RFC 7643/7644).
const (
	SCIMSchemaUser            = "urn:ietf:params:scim:schemas:core:2.0:User"
	SCIMSchemaGroup           = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SCIMSchemaListResponse    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SCIMSchemaPatchOp         = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SCIMSchemaError           = "urn:ietf:params:scim:api:messages:2.0:Error"
	SCIMSchemaSPConfig        = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SCIMSchemaResourceType    = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SCIMSchemaSchema          = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	SCIMContentType           = "application/scim+json"
	SCIMDefaultCount          = 100
	SCIMMaxCount              = 200
	SCIMMaxPatchOperations    = 1000
	SCIMMaxGroupMembers       = 10000
	scimPublicBasePath        = "/scim/v2"
	SCIMTypeInvalidFilter     = "invalidFilter"
	SCIMTypeInvalidValue      = "invalidValue"
	SCIMTypeInvalidPath       = "invalidPath"
	SCIMTypeInvalidSyntax     = "invalidSyntax"
	SCIMTypeUniqueness        = "uniqueness"
	SCIMTypeNoTarget          = "noTarget"
	SCIMTypeMutability        = "mutability"
	DirectorySourceSCIM       = "scim"
	DirectorySourceJIT        = "jit"
	SCIMFilterAttrUserName    = "userName"
	SCIMFilterAttrDisplayName = "displayName"
)

// SCIMError is a SCIM protocol error. It maps to the SCIM Error response.
type SCIMError struct {
	Status   int
	SCIMType string
	Detail   string
}

func (e *SCIMError) Error() string {
	return fmt.Sprintf("scim %d %s: %s", e.Status, e.SCIMType, e.Detail)
}

// NewSCIMBadRequest builds a SCIM 400 error.
func NewSCIMBadRequest(scimType string, format string, args ...any) *SCIMError {
	return scimBadRequest(scimType, format, args...)
}

func scimBadRequest(scimType string, format string, args ...any) *SCIMError {
	return &SCIMError{Status: 400, SCIMType: scimType, Detail: fmt.Sprintf(format, args...)}
}

// SCIMErrorBody is the SCIM Error wire shape.
type SCIMErrorBody struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// NewSCIMErrorBody renders a SCIM error response body.
func NewSCIMErrorBody(err *SCIMError) SCIMErrorBody {
	return SCIMErrorBody{Schemas: []string{SCIMSchemaError}, Status: strconv.Itoa(err.Status), SCIMType: err.SCIMType, Detail: err.Detail}
}

// SCIMFilter is a parsed `attr eq "value"` filter.
type SCIMFilter struct {
	Attribute string
	Value     string
}

var scimFilterPattern = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9._:-]*)\s+([A-Za-z]+)\s+("(?:[^"\\]|\\.)*")\s*$`)

// ParseSCIMFilter parses a SCIM filter. Only `eq` on the given attribute
// is supported; every other expression is rejected with invalidFilter.
// An empty filter returns nil.
func ParseSCIMFilter(raw string, attribute string) (*SCIMFilter, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	match := scimFilterPattern.FindStringSubmatch(raw)
	if match == nil {
		return nil, scimBadRequest(SCIMTypeInvalidFilter, "only %s eq \"value\" filters are supported", attribute)
	}
	if !strings.EqualFold(match[1], attribute) {
		return nil, scimBadRequest(SCIMTypeInvalidFilter, "filtering is supported on %s only", attribute)
	}
	if !strings.EqualFold(match[2], "eq") {
		return nil, scimBadRequest(SCIMTypeInvalidFilter, "only the eq operator is supported")
	}
	var value string
	if err := json.Unmarshal([]byte(match[3]), &value); err != nil {
		return nil, scimBadRequest(SCIMTypeInvalidFilter, "filter value is not a valid string")
	}
	return &SCIMFilter{Attribute: attribute, Value: value}, nil
}

// SCIMPage is a 1-based SCIM page request.
type SCIMPage struct {
	StartIndex int
	Count      int
}

// ParseSCIMPage parses startIndex and count with RFC 7644 defaults.
func ParseSCIMPage(startIndex string, count string) (SCIMPage, error) {
	page := SCIMPage{StartIndex: 1, Count: SCIMDefaultCount}
	if strings.TrimSpace(startIndex) != "" {
		value, err := strconv.Atoi(strings.TrimSpace(startIndex))
		if err != nil {
			return page, scimBadRequest(SCIMTypeInvalidValue, "startIndex must be an integer")
		}
		if value > 1 {
			page.StartIndex = value
		}
	}
	if strings.TrimSpace(count) != "" {
		value, err := strconv.Atoi(strings.TrimSpace(count))
		if err != nil {
			return page, scimBadRequest(SCIMTypeInvalidValue, "count must be an integer")
		}
		page.Count = max(0, min(value, SCIMMaxCount))
	}
	return page, nil
}

// SCIMListResponse is the SCIM ListResponse wire shape.
type SCIMListResponse[T any] struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []T      `json:"Resources"`
}

// NewSCIMListResponse builds a list response for one page.
func NewSCIMListResponse[T any](resources []T, total int, page SCIMPage) SCIMListResponse[T] {
	if resources == nil {
		resources = []T{}
	}
	return SCIMListResponse[T]{
		Schemas:      []string{SCIMSchemaListResponse},
		TotalResults: total,
		StartIndex:   page.StartIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
}

// SCIMMeta is resource metadata.
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
}

// SCIMName is the SCIM complex name attribute.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// SCIMEmail is one SCIM email value.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMRef references a user or group from another resource.
type SCIMRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMUser is the SCIM User wire shape.
type SCIMUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *SCIMName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	Groups      []SCIMRef   `json:"groups,omitempty"`
	Meta        *SCIMMeta   `json:"meta,omitempty"`
}

// SCIMGroup is the SCIM Group wire shape.
type SCIMGroup struct {
	Schemas     []string  `json:"schemas"`
	ID          string    `json:"id,omitempty"`
	ExternalID  string    `json:"externalId,omitempty"`
	DisplayName string    `json:"displayName"`
	Members     []SCIMRef `json:"members,omitempty"`
	Meta        *SCIMMeta `json:"meta,omitempty"`
}

// SCIMPatchRequest is the SCIM PatchOp wire shape.
type SCIMPatchRequest struct {
	Schemas    []string             `json:"schemas"`
	Operations []SCIMPatchOperation `json:"Operations"`
}

// SCIMPatchOperation is one PATCH operation.
type SCIMPatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// NewSCIMUser renders a directory user as a SCIM User.
func NewSCIMUser(user ports.DirectoryUser) SCIMUser {
	active := user.Active
	out := SCIMUser{
		Schemas:     []string{SCIMSchemaUser},
		ID:          user.ID,
		ExternalID:  user.ExternalID,
		UserName:    user.UserName,
		DisplayName: user.DisplayName,
		Active:      &active,
		Meta: &SCIMMeta{
			ResourceType: "User",
			Created:      user.CreatedAt.UTC(),
			LastModified: user.UpdatedAt.UTC(),
			Location:     scimPublicBasePath + "/Users/" + user.ID,
		},
	}
	if user.GivenName != "" || user.FamilyName != "" {
		out.Name = &SCIMName{GivenName: user.GivenName, FamilyName: user.FamilyName, Formatted: strings.TrimSpace(user.GivenName + " " + user.FamilyName)}
	}
	if user.Email != "" {
		out.Emails = []SCIMEmail{{Value: user.Email, Type: "work", Primary: true}}
	}
	for _, group := range user.Groups {
		out.Groups = append(out.Groups, SCIMRef{Value: group.ID, Display: group.DisplayName, Ref: scimPublicBasePath + "/Groups/" + group.ID})
	}
	return out
}

// NewSCIMGroup renders a directory group as a SCIM Group.
func NewSCIMGroup(group ports.DirectoryGroup, includeMembers bool) SCIMGroup {
	out := SCIMGroup{
		Schemas:     []string{SCIMSchemaGroup},
		ID:          group.ID,
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Meta: &SCIMMeta{
			ResourceType: "Group",
			Created:      group.CreatedAt.UTC(),
			LastModified: group.UpdatedAt.UTC(),
			Location:     scimPublicBasePath + "/Groups/" + group.ID,
		},
	}
	if includeMembers {
		for _, id := range group.MemberIDs {
			out.Members = append(out.Members, SCIMRef{Value: id, Ref: scimPublicBasePath + "/Users/" + id})
		}
	}
	return out
}

// ApplySCIMUser copies a SCIM User (POST or PUT body) onto a directory user.
// When the body omits active, the user's current active value is kept.
func ApplySCIMUser(user ports.DirectoryUser, in SCIMUser) (ports.DirectoryUser, error) {
	user.UserName = strings.TrimSpace(in.UserName)
	user.ExternalID = strings.TrimSpace(in.ExternalID)
	user.DisplayName = strings.TrimSpace(in.DisplayName)
	user.GivenName, user.FamilyName = "", ""
	if in.Name != nil {
		user.GivenName = strings.TrimSpace(in.Name.GivenName)
		user.FamilyName = strings.TrimSpace(in.Name.FamilyName)
		if user.DisplayName == "" {
			user.DisplayName = strings.TrimSpace(in.Name.Formatted)
		}
	}
	user.Email = primaryEmail(in.Emails)
	if in.Active != nil {
		user.Active = *in.Active
	}
	return user, validateDirectoryUser(user)
}

func primaryEmail(emails []SCIMEmail) string {
	for _, email := range emails {
		if email.Primary && strings.TrimSpace(email.Value) != "" {
			return strings.TrimSpace(email.Value)
		}
	}
	for _, email := range emails {
		if strings.TrimSpace(email.Value) != "" {
			return strings.TrimSpace(email.Value)
		}
	}
	return ""
}

func validateDirectoryUser(user ports.DirectoryUser) error {
	checks := []struct {
		field    string
		value    string
		maxLen   int
		required bool
	}{
		{"userName", user.UserName, maxEmailLength, true},
		{"externalId", user.ExternalID, maxSubjectLength, false},
		{"displayName", user.DisplayName, maxShortTextLength, false},
		{"name.givenName", user.GivenName, maxShortTextLength, false},
		{"name.familyName", user.FamilyName, maxShortTextLength, false},
		{"emails", user.Email, maxEmailLength, false},
	}
	for _, check := range checks {
		if err := checkText(check.field, check.value, check.maxLen, check.required); err != nil {
			return scimBadRequest(SCIMTypeInvalidValue, "%s", strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
		}
	}
	return nil
}

// ApplySCIMUserPatch applies PATCH operations to a user. Attributes Cerebro does
// not store are accepted and ignored so IdPs that push extra profile fields keep
// syncing.
func ApplySCIMUserPatch(user ports.DirectoryUser, request SCIMPatchRequest) (ports.DirectoryUser, error) {
	if len(request.Operations) == 0 || len(request.Operations) > SCIMMaxPatchOperations {
		return user, scimBadRequest(SCIMTypeInvalidSyntax, "PATCH requires 1 to %d operations", SCIMMaxPatchOperations)
	}
	for _, operation := range request.Operations {
		op := strings.ToLower(strings.TrimSpace(operation.Op))
		path := strings.TrimSpace(operation.Path)
		var err error
		switch op {
		case "add", "replace":
			if path == "" {
				user, err = applyUserValueObject(user, operation.Value)
			} else {
				user, err = setUserPath(user, path, operation.Value)
			}
		case "remove":
			if path == "" {
				return user, scimBadRequest(SCIMTypeNoTarget, "remove requires a path")
			}
			user, err = removeUserPath(user, path)
		default:
			return user, scimBadRequest(SCIMTypeInvalidSyntax, "unsupported PATCH op %q", operation.Op)
		}
		if err != nil {
			return user, err
		}
	}
	return user, validateDirectoryUser(user)
}

func applyUserValueObject(user ports.DirectoryUser, raw json.RawMessage) (ports.DirectoryUser, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return user, scimBadRequest(SCIMTypeInvalidValue, "PATCH without a path requires an object value")
	}
	for key, value := range fields {
		var err error
		if user, err = setUserPath(user, key, value); err != nil {
			return user, err
		}
	}
	return user, nil
}

var emailValuePathPattern = regexp.MustCompile(`(?i)^emails\[[^\]]*\]\.value$`)

func setUserPath(user ports.DirectoryUser, path string, raw json.RawMessage) (ports.DirectoryUser, error) {
	attr := strings.ToLower(strings.TrimPrefix(path, SCIMSchemaUser+":"))
	var err error
	switch {
	case attr == "active":
		user.Active, err = scimBool(raw)
	case attr == "username":
		user.UserName, err = scimString(raw, "userName")
	case attr == "displayname":
		user.DisplayName, err = scimString(raw, "displayName")
	case attr == "externalid":
		user.ExternalID, err = scimString(raw, "externalId")
	case attr == "name.givenname":
		user.GivenName, err = scimString(raw, "name.givenName")
	case attr == "name.familyname":
		user.FamilyName, err = scimString(raw, "name.familyName")
	case attr == "name":
		var name SCIMName
		if err := json.Unmarshal(raw, &name); err != nil {
			return user, scimBadRequest(SCIMTypeInvalidValue, "name must be an object")
		}
		user.GivenName, user.FamilyName = strings.TrimSpace(name.GivenName), strings.TrimSpace(name.FamilyName)
	case attr == "emails":
		var emails []SCIMEmail
		if err := json.Unmarshal(raw, &emails); err != nil {
			return user, scimBadRequest(SCIMTypeInvalidValue, "emails must be an array")
		}
		if email := primaryEmail(emails); email != "" {
			user.Email = email
		}
	case emailValuePathPattern.MatchString(attr):
		user.Email, err = scimString(raw, "emails.value")
	}
	return user, err
}

func removeUserPath(user ports.DirectoryUser, path string) (ports.DirectoryUser, error) {
	attr := strings.ToLower(strings.TrimPrefix(path, SCIMSchemaUser+":"))
	switch {
	case attr == "username", attr == "active":
		return user, scimBadRequest(SCIMTypeMutability, "%s cannot be removed", path)
	case attr == "displayname":
		user.DisplayName = ""
	case attr == "externalid":
		user.ExternalID = ""
	case attr == "name":
		user.GivenName, user.FamilyName = "", ""
	case attr == "name.givenname":
		user.GivenName = ""
	case attr == "name.familyname":
		user.FamilyName = ""
	case attr == "emails", emailValuePathPattern.MatchString(attr):
		user.Email = ""
	}
	return user, nil
}

func scimBool(raw json.RawMessage) (bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}
	// Some IdPs (notably Entra ID) send booleans as "True"/"False" strings.
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if parsed, err := strconv.ParseBool(strings.TrimSpace(text)); err == nil {
			return parsed, nil
		}
	}
	return false, scimBadRequest(SCIMTypeInvalidValue, "active must be a boolean")
}

func scimString(raw json.RawMessage, field string) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", scimBadRequest(SCIMTypeInvalidValue, "%s must be a string", field)
	}
	return strings.TrimSpace(value), nil
}

// ApplySCIMGroup copies a SCIM Group (POST or PUT body) onto a directory group.
func ApplySCIMGroup(group ports.DirectoryGroup, in SCIMGroup) (ports.DirectoryGroup, error) {
	group.DisplayName = strings.TrimSpace(in.DisplayName)
	group.ExternalID = strings.TrimSpace(in.ExternalID)
	group.MemberIDs = nil
	for _, member := range in.Members {
		group.MemberIDs = appendMember(group.MemberIDs, member.Value)
	}
	return group, validateDirectoryGroup(group)
}

func validateDirectoryGroup(group ports.DirectoryGroup) error {
	if err := checkText("displayName", group.DisplayName, maxShortTextLength, true); err != nil {
		return scimBadRequest(SCIMTypeInvalidValue, "displayName is required and must be at most %d characters", maxShortTextLength)
	}
	if err := checkText("externalId", group.ExternalID, maxSubjectLength, false); err != nil {
		return scimBadRequest(SCIMTypeInvalidValue, "externalId is invalid")
	}
	if len(group.MemberIDs) > SCIMMaxGroupMembers {
		return scimBadRequest(SCIMTypeInvalidValue, "groups allow at most %d members", SCIMMaxGroupMembers)
	}
	return nil
}

func appendMember(members []string, id string) []string {
	id = strings.TrimSpace(id)
	if id == "" || containsString(members, id) {
		return members
	}
	return append(members, id)
}

var memberFilterPathPattern = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+("(?:[^"\\]|\\.)*")\s*\]$`)

// ApplySCIMGroupPatch applies PATCH operations to a group: displayName and
// externalId changes, and member add, remove, and replace.
func ApplySCIMGroupPatch(group ports.DirectoryGroup, request SCIMPatchRequest) (ports.DirectoryGroup, error) {
	if len(request.Operations) == 0 || len(request.Operations) > SCIMMaxPatchOperations {
		return group, scimBadRequest(SCIMTypeInvalidSyntax, "PATCH requires 1 to %d operations", SCIMMaxPatchOperations)
	}
	for _, operation := range request.Operations {
		op := strings.ToLower(strings.TrimSpace(operation.Op))
		path := strings.TrimSpace(operation.Path)
		var err error
		switch op {
		case "add", "replace":
			if path == "" {
				group, err = applyGroupValueObject(group, op, operation.Value)
			} else {
				group, err = setGroupPath(group, op, path, operation.Value)
			}
		case "remove":
			group, err = removeGroupPath(group, path, operation.Value)
		default:
			return group, scimBadRequest(SCIMTypeInvalidSyntax, "unsupported PATCH op %q", operation.Op)
		}
		if err != nil {
			return group, err
		}
	}
	return group, validateDirectoryGroup(group)
}

func applyGroupValueObject(group ports.DirectoryGroup, op string, raw json.RawMessage) (ports.DirectoryGroup, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return group, scimBadRequest(SCIMTypeInvalidValue, "PATCH without a path requires an object value")
	}
	for key, value := range fields {
		if strings.EqualFold(key, "id") {
			continue
		}
		var err error
		if group, err = setGroupPath(group, op, key, value); err != nil {
			return group, err
		}
	}
	return group, nil
}

func setGroupPath(group ports.DirectoryGroup, op string, path string, raw json.RawMessage) (ports.DirectoryGroup, error) {
	attr := strings.ToLower(strings.TrimPrefix(path, SCIMSchemaGroup+":"))
	var err error
	switch attr {
	case "displayname":
		group.DisplayName, err = scimString(raw, "displayName")
	case "externalid":
		group.ExternalID, err = scimString(raw, "externalId")
	case "members":
		members, parseErr := scimMemberValues(raw)
		if parseErr != nil {
			return group, parseErr
		}
		if op == "replace" {
			group.MemberIDs = nil
		}
		for _, id := range members {
			group.MemberIDs = appendMember(group.MemberIDs, id)
		}
	default:
		return group, scimBadRequest(SCIMTypeInvalidPath, "unsupported group attribute %q", path)
	}
	return group, err
}

func removeGroupPath(group ports.DirectoryGroup, path string, raw json.RawMessage) (ports.DirectoryGroup, error) {
	if path == "" {
		return group, scimBadRequest(SCIMTypeNoTarget, "remove requires a path")
	}
	if match := memberFilterPathPattern.FindStringSubmatch(path); match != nil {
		var id string
		if err := json.Unmarshal([]byte(match[1]), &id); err != nil {
			return group, scimBadRequest(SCIMTypeInvalidPath, "invalid member filter")
		}
		group.MemberIDs = removeMembers(group.MemberIDs, []string{id})
		return group, nil
	}
	switch strings.ToLower(path) {
	case "members":
		if len(raw) == 0 || string(raw) == "null" {
			group.MemberIDs = nil
			return group, nil
		}
		members, err := scimMemberValues(raw)
		if err != nil {
			return group, err
		}
		group.MemberIDs = removeMembers(group.MemberIDs, members)
		return group, nil
	case "externalid":
		group.ExternalID = ""
		return group, nil
	case "displayname":
		return group, scimBadRequest(SCIMTypeMutability, "displayName cannot be removed")
	default:
		return group, scimBadRequest(SCIMTypeInvalidPath, "unsupported group path %q", path)
	}
}

func scimMemberValues(raw json.RawMessage) ([]string, error) {
	var members []SCIMRef
	if err := json.Unmarshal(raw, &members); err != nil {
		var single SCIMRef
		if errSingle := json.Unmarshal(raw, &single); errSingle != nil || single.Value == "" {
			return nil, scimBadRequest(SCIMTypeInvalidValue, "members must be an array of {\"value\": id}")
		}
		members = []SCIMRef{single}
	}
	ids := make([]string, 0, len(members))
	for _, member := range members {
		if strings.TrimSpace(member.Value) == "" {
			return nil, scimBadRequest(SCIMTypeInvalidValue, "member value is required")
		}
		ids = append(ids, strings.TrimSpace(member.Value))
	}
	return ids, nil
}

func removeMembers(members []string, remove []string) []string {
	kept := members[:0:0]
	for _, id := range members {
		if !containsString(remove, id) {
			kept = append(kept, id)
		}
	}
	return kept
}

// AsSCIMError extracts a SCIM error, wrapping other validation errors as invalidValue.
func AsSCIMError(err error) (*SCIMError, bool) {
	var scimErr *SCIMError
	if errors.As(err, &scimErr) {
		return scimErr, true
	}
	if errors.Is(err, ErrInvalid) {
		return scimBadRequest(SCIMTypeInvalidValue, "%s", err.Error()), true
	}
	return nil, false
}
