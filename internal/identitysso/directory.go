package identitysso

import (
	"slices"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// DirectoryUserView is the admin and login lookup shape for a directory user.
// Groups is a display union. Only SCIMGroups, the SCIM-managed memberships,
// may be combined with fresh assertion groups to authorize a session;
// JITGroups are the groups seen at the latest login and are display only.
type DirectoryUserView struct {
	ID           string     `json:"id"`
	UserName     string     `json:"userName"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	Active       bool       `json:"active"`
	Groups       []string   `json:"groups"`
	SCIMGroups   []string   `json:"scimGroups"`
	JITGroups    []string   `json:"jitGroups"`
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
	scimGroups := make([]string, 0, len(user.Groups))
	for _, group := range user.Groups {
		if !containsString(scimGroups, group.DisplayName) {
			scimGroups = append(scimGroups, group.DisplayName)
		}
	}
	groups := slices.Clone(scimGroups)
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
		SCIMGroups:   scimGroups,
		JITGroups:    nonNil(slices.Clone(user.JITGroups)),
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

// CheckLoginUser refuses a login or session for a deprovisioned or inactive
// directory user, or one bound to a different IdP subject.
func CheckLoginUser(user ports.DirectoryUser, subject string) error {
	switch {
	case user.DeletedAt != nil:
		return ErrUserDeprovisioned
	case !user.Active:
		return ErrUserInactive
	case user.Subject != "" && user.Subject != subject:
		return ErrSubjectMismatch
	}
	return nil
}

// ApplyJITLogin records a login on an existing user. It writes only the
// last-login time, the subject binding, and, for just-in-time users, the
// assertion groups, which replace the stored ones. Active state, source, and
// profile attributes are never written by a login.
func ApplyJITLogin(user *ports.DirectoryUser, input JITUserInput, now time.Time) error {
	if err := CheckLoginUser(*user, input.Subject); err != nil {
		return err
	}
	at := now.UTC()
	user.LastLoginAt = &at
	user.Subject = input.Subject
	if user.Source == DirectorySourceJIT {
		user.JITGroups = slices.Clone(nonNil(input.Groups))
	}
	return nil
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

// MatchDirectoryUser picks the directory user a login or session belongs to
// from candidates found by subject or email on one connection. Live users win
// over tombstones, a user bound to the subject wins over an email match, and
// SCIM users win over just-in-time users. It returns nil when no candidate
// matches. The Postgres session lookup applies the same order.
func MatchDirectoryUser(candidates []ports.DirectoryUser, subject string, email string) *ports.DirectoryUser {
	var best *ports.DirectoryUser
	var bestRank [3]int
	for i := range candidates {
		user := &candidates[i]
		subjectMatch := subject != "" && user.Subject == subject
		emailMatch := email != "" && (strings.EqualFold(user.Email, email) || strings.EqualFold(user.UserName, email))
		if !subjectMatch && !emailMatch {
			continue
		}
		rank := [3]int{boolRank(user.DeletedAt != nil), boolRank(!subjectMatch), boolRank(user.Source != DirectorySourceSCIM)}
		if best == nil || slices.Compare(rank[:], bestRank[:]) < 0 || (rank == bestRank && user.ID < best.ID) {
			best, bestRank = user, rank
		}
	}
	return best
}

func boolRank(value bool) int {
	if value {
		return 1
	}
	return 0
}

// SessionMatchForUser selects the sessions that belong to a directory user on
// its connection: any session whose subject is the user's subject or external
// ID, or whose email matches the user's email or userName.
func SessionMatchForUser(user ports.DirectoryUser) ports.SSOSessionMatch {
	match := ports.SSOSessionMatch{ConnectionID: user.ConnectionID}
	return AddUserToSessionMatch(match, user)
}

// AddUserToSessionMatch extends match with a user's subjects and emails.
func AddUserToSessionMatch(match ports.SSOSessionMatch, user ports.DirectoryUser) ports.SSOSessionMatch {
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

// AffectedGroupMembers returns the user IDs whose session roles may change when
// a group goes from before to after: members added or removed, or every member
// of either version when the display name, which role mappings match, changes.
func AffectedGroupMembers(before ports.DirectoryGroup, after ports.DirectoryGroup) []string {
	if before.DisplayName != after.DisplayName {
		return unionStrings(before.MemberIDs, after.MemberIDs)
	}
	var affected []string
	for _, id := range before.MemberIDs {
		if !slices.Contains(after.MemberIDs, id) && !slices.Contains(affected, id) {
			affected = append(affected, id)
		}
	}
	for _, id := range after.MemberIDs {
		if !slices.Contains(before.MemberIDs, id) && !slices.Contains(affected, id) {
			affected = append(affected, id)
		}
	}
	return affected
}

func unionStrings(a []string, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	for _, value := range append(slices.Clone(a), b...) {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

// AdoptSCIMUser marks a user SCIM-managed. A just-in-time user taken over by
// SCIM loses its login-time groups, and a deprovisioned tombstone is revived.
func AdoptSCIMUser(user *ports.DirectoryUser, now time.Time) {
	if user.Source != DirectorySourceSCIM {
		user.JITGroups = nil
	}
	user.Source = DirectorySourceSCIM
	user.DeletedAt = nil
	user.UpdatedAt = now
}
