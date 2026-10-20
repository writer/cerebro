package identitysso

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// DirectoryUserView is the admin and login lookup shape for a directory user.
type DirectoryUserView struct {
	ID           string     `json:"id"`
	UserName     string     `json:"userName"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	Active       bool       `json:"active"`
	Groups       []string   `json:"groups"`
	Source       string     `json:"source"`
	ConnectionID string     `json:"connectionId"`
	LastLoginAt  *time.Time `json:"lastLoginAt,omitempty"`
}

// DirectoryGroupView is the admin shape for a directory group.
type DirectoryGroupView struct {
	ID           string `json:"id"`
	DisplayName  string `json:"displayName"`
	MemberCount  int    `json:"memberCount"`
	ConnectionID string `json:"connectionId"`
}

// JITUserInput is the login-time upsert request for a user.
type JITUserInput struct {
	ConnectionID string   `json:"connectionId"`
	Subject      string   `json:"subject"`
	Email        string   `json:"email"`
	Name         string   `json:"name"`
	Groups       []string `json:"groups"`
}

// NewDirectoryUserView converts a stored user to its admin shape. Groups are
// the SCIM group display names plus, for just-in-time users, the IdP groups
// seen at the latest login.
func NewDirectoryUserView(user ports.DirectoryUser) DirectoryUserView {
	groups := make([]string, 0, len(user.Groups)+len(user.JITGroups))
	for _, group := range user.Groups {
		if !containsString(groups, group.DisplayName) {
			groups = append(groups, group.DisplayName)
		}
	}
	for _, group := range user.JITGroups {
		if !containsString(groups, group) {
			groups = append(groups, group)
		}
	}
	name := user.DisplayName
	if name == "" {
		name = strings.TrimSpace(user.GivenName + " " + user.FamilyName)
	}
	email := user.Email
	if email == "" && strings.Contains(user.UserName, "@") {
		email = user.UserName
	}
	view := DirectoryUserView{
		ID:           user.ID,
		UserName:     user.UserName,
		Email:        email,
		Name:         name,
		Active:       user.Active,
		Groups:       groups,
		Source:       user.Source,
		ConnectionID: user.ConnectionID,
	}
	if user.LastLoginAt != nil {
		at := user.LastLoginAt.UTC()
		view.LastLoginAt = &at
	}
	return view
}

// NewDirectoryGroupView converts a stored group to its admin shape.
func NewDirectoryGroupView(group ports.DirectoryGroup) DirectoryGroupView {
	return DirectoryGroupView{ID: group.ID, DisplayName: group.DisplayName, MemberCount: group.MemberCount, ConnectionID: group.ConnectionID}
}

// NormalizeJITInput validates a login-time upsert request.
func NormalizeJITInput(input JITUserInput) (JITUserInput, error) {
	input.ConnectionID = strings.TrimSpace(input.ConnectionID)
	if !ValidResourceID(input.ConnectionID) {
		return input, invalid("connectionId is invalid")
	}
	input.Subject = strings.TrimSpace(input.Subject)
	if err := checkText("subject", input.Subject, maxSubjectLength, true); err != nil {
		return input, err
	}
	input.Email = strings.TrimSpace(input.Email)
	if err := checkText("email", input.Email, maxEmailLength, true); err != nil {
		return input, err
	}
	if !strings.Contains(input.Email, "@") {
		return input, invalid("email must be an email address")
	}
	input.Name = strings.TrimSpace(input.Name)
	if err := checkText("name", input.Name, maxShortTextLength, false); err != nil {
		return input, err
	}
	groups, err := normalizeStringList("groups", input.Groups, maxSessionClaimValues, maxShortTextLength)
	if err != nil {
		return input, err
	}
	input.Groups = groups
	return input, nil
}

// ApplyJITLogin records a login on an existing user. SCIM-managed attributes
// are left alone; just-in-time users take the latest IdP profile and groups.
func ApplyJITLogin(user ports.DirectoryUser, input JITUserInput, now time.Time) ports.DirectoryUser {
	at := now.UTC()
	user.LastLoginAt = &at
	if user.Subject == "" || user.Source == DirectorySourceJIT {
		user.Subject = input.Subject
	}
	if user.Source == DirectorySourceJIT {
		user.Email = input.Email
		if input.Name != "" {
			user.DisplayName = input.Name
		}
		user.JITGroups = input.Groups
	}
	user.UpdatedAt = now
	return user
}

// NewJITUser builds a just-in-time user for a first login.
func NewJITUser(tenantID string, id string, input JITUserInput, now time.Time) ports.DirectoryUser {
	at := now.UTC()
	return ports.DirectoryUser{
		TenantID:     tenantID,
		ID:           id,
		ConnectionID: input.ConnectionID,
		Source:       DirectorySourceJIT,
		UserName:     input.Email,
		Subject:      input.Subject,
		Email:        input.Email,
		DisplayName:  input.Name,
		Active:       true,
		JITGroups:    input.Groups,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastLoginAt:  &at,
	}
}

// SessionMatchForUser selects the sessions that belong to a directory user:
// any session whose subject is the user's subject or external ID, or whose
// email matches the user's email or userName.
func SessionMatchForUser(user ports.DirectoryUser) ports.SSOSessionMatch {
	var match ports.SSOSessionMatch
	for _, subject := range []string{user.Subject, user.ExternalID} {
		if subject = strings.TrimSpace(subject); subject != "" && !containsString(match.Subjects, subject) {
			match.Subjects = append(match.Subjects, subject)
		}
	}
	for _, email := range []string{user.Email, user.UserName} {
		email = strings.ToLower(strings.TrimSpace(email))
		if strings.Contains(email, "@") && !containsString(match.Emails, email) {
			match.Emails = append(match.Emails, email)
		}
	}
	return match
}
