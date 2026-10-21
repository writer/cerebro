package identitysso

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

// fakeStore is an in-memory ports.IdentitySSOStore with the same uniqueness
// and cascade rules as the Postgres store.
type fakeStore struct {
	mu          sync.Mutex
	connections map[string]ports.SSOConnection
	policies    map[string]ports.SSOPolicy
	sessions    map[string]ports.SSOSession
	tokens      map[string]ports.SCIMToken
	users       map[string]ports.DirectoryUser
	groups      map[string]ports.DirectoryGroup
	assertions  []ports.SAMLAssertionUse
	touches     int
}

var _ ports.IdentitySSOStore = (*fakeStore)(nil)

func newFakeStore() *fakeStore {
	return &fakeStore{
		connections: map[string]ports.SSOConnection{},
		policies:    map[string]ports.SSOPolicy{},
		sessions:    map[string]ports.SSOSession{},
		tokens:      map[string]ports.SCIMToken{},
		users:       map[string]ports.DirectoryUser{},
		groups:      map[string]ports.DirectoryGroup{},
	}
}

func key(parts ...string) string { return strings.Join(parts, "\x00") }

func (s *fakeStore) ListSSOConnections(_ context.Context, tenantID string) ([]ports.SSOConnection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ports.SSOConnection{}
	for _, conn := range s.connections {
		if conn.TenantID == tenantID {
			out = append(out, conn)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *fakeStore) GetSSOConnection(_ context.Context, tenantID string, id string) (*ports.SSOConnection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, ok := s.connections[key(tenantID, id)]
	if !ok {
		return nil, ports.ErrSSOConnectionNotFound
	}
	return &conn, nil
}

func (s *fakeStore) PutSSOConnection(_ context.Context, conn *ports.SSOConnection, maxConnections int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, other := range s.connections {
		if other.TenantID != conn.TenantID || other.ID == conn.ID {
			continue
		}
		count++
		for _, domain := range conn.Domains {
			if slices.Contains(other.Domains, domain) {
				return ports.ErrSSODomainConflict
			}
		}
	}
	if count >= maxConnections {
		return ports.ErrSSOConnectionLimit
	}
	if s.locksOut(conn.TenantID, conn.ID, conn) {
		return ports.ErrSSOLastActiveConnection
	}
	s.connections[key(conn.TenantID, conn.ID)] = *conn
	return nil
}

// locksOut reports whether replacing connection id with next (nil deletes it)
// would leave an enforced tenant without an active connection.
func (s *fakeStore) locksOut(tenantID string, id string, next *ports.SSOConnection) bool {
	policy, ok := s.policies[tenantID]
	if !ok || !policy.Enforced {
		return false
	}
	if next != nil && next.Status == ports.SSOStatusActive {
		return false
	}
	for _, other := range s.connections {
		if other.TenantID == tenantID && other.ID != id && other.Status == ports.SSOStatusActive {
			return false
		}
	}
	return true
}

func (s *fakeStore) UpdateSSOConnection(_ context.Context, tenantID string, id string, maxConnections int, mutate func(ports.SSOConnection) (ports.SSOConnectionUpdate, error)) (*ports.SSOConnection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.connections[key(tenantID, id)]
	if !ok {
		return nil, ports.ErrSSOConnectionNotFound
	}
	update, err := mutate(current)
	if err != nil {
		return nil, err
	}
	next := update.Connection
	for _, other := range s.connections {
		if other.TenantID != tenantID || other.ID == id {
			continue
		}
		for _, domain := range next.Domains {
			if slices.Contains(other.Domains, domain) {
				return nil, ports.ErrSSODomainConflict
			}
		}
	}
	if s.locksOut(tenantID, id, &next) {
		return nil, ports.ErrSSOLastActiveConnection
	}
	s.connections[key(tenantID, id)] = next
	if update.RevokeSessions {
		s.revokeConnectionSessions(tenantID, id, next.UpdatedAt)
	}
	return &next, nil
}

func (s *fakeStore) revokeConnectionSessions(tenantID string, connectionID string, at time.Time) {
	for k, session := range s.sessions {
		if session.TenantID == tenantID && session.ConnectionID == connectionID && session.RevokedAt == nil {
			revokedAt := at
			session.RevokedAt = &revokedAt
			s.sessions[k] = session
		}
	}
}

func (s *fakeStore) DeleteSSOConnection(_ context.Context, tenantID string, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[key(tenantID, id)]; !ok {
		return ports.ErrSSOConnectionNotFound
	}
	if s.locksOut(tenantID, id, nil) {
		return ports.ErrSSOLastActiveConnection
	}
	delete(s.connections, key(tenantID, id))
	for k, v := range s.sessions {
		if v.TenantID == tenantID && v.ConnectionID == id {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.tokens {
		if v.TenantID == tenantID && v.ConnectionID == id {
			delete(s.tokens, k)
		}
	}
	for k, v := range s.users {
		if v.TenantID == tenantID && v.ConnectionID == id {
			delete(s.users, k)
		}
	}
	for k, v := range s.groups {
		if v.TenantID == tenantID && v.ConnectionID == id {
			delete(s.groups, k)
		}
	}
	return nil
}

func (s *fakeStore) GetSSOPolicy(_ context.Context, tenantID string) (*ports.SSOPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.policies[tenantID]
	if !ok {
		return nil, ports.ErrSSOPolicyNotFound
	}
	return &policy, nil
}

func (s *fakeStore) PutSSOPolicy(_ context.Context, policy *ports.SSOPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy.Enforced {
		active := false
		for _, conn := range s.connections {
			active = active || (conn.TenantID == policy.TenantID && conn.Status == ports.SSOStatusActive)
		}
		if !active {
			return ports.ErrSSONoActiveConnection
		}
	}
	s.policies[policy.TenantID] = *policy
	return nil
}

func (s *fakeStore) CreateSSOSession(_ context.Context, session *ports.SSOSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.TokenHash]; ok {
		return ports.ErrSSOSessionExists
	}
	s.sessions[session.TokenHash] = *session
	return nil
}

func (s *fakeStore) GetSSOSession(_ context.Context, tenantID string, tokenHash string) (*ports.SSOSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[tokenHash]
	if !ok || session.TenantID != tenantID {
		return nil, ports.ErrSSOSessionNotFound
	}
	conn, ok := s.connections[key(tenantID, session.ConnectionID)]
	if !ok || conn.Status != ports.SSOStatusActive {
		return nil, ports.ErrSSOSessionNotFound
	}
	candidates := []ports.DirectoryUser{}
	for _, user := range s.users {
		if user.TenantID == tenantID && user.ConnectionID == session.ConnectionID {
			candidates = append(candidates, user)
		}
	}
	if user := sso.MatchDirectoryUser(candidates, session.Subject, session.Email); user != nil && (!user.Active || user.DeletedAt != nil) {
		return nil, ports.ErrSSOSessionNotFound
	}
	return &session, nil
}

func (s *fakeStore) TouchSSOSession(_ context.Context, tenantID string, tokenHash string, seenAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[tokenHash]
	if !ok || session.TenantID != tenantID {
		return ports.ErrSSOSessionNotFound
	}
	session.LastSeenAt = seenAt
	s.sessions[tokenHash] = session
	s.touches++
	return nil
}

func (s *fakeStore) DeleteSSOSession(_ context.Context, tenantID string, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.sessions[tokenHash]; ok && session.TenantID == tenantID {
		delete(s.sessions, tokenHash)
	}
	return nil
}

func (s *fakeStore) ListSSOSessions(_ context.Context, tenantID string, subject string, _ time.Time, limit int) ([]ports.SSOSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ports.SSOSession{}
	for _, session := range s.sessions {
		if session.TenantID != tenantID || session.RevokedAt != nil {
			continue
		}
		if subject != "" && session.Subject != subject && !strings.EqualFold(session.Email, subject) {
			continue
		}
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TokenHash < out[j].TokenHash })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *fakeStore) RevokeSSOSessions(_ context.Context, tenantID string, match ports.SSOSessionMatch, revokedAt time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for k, session := range s.sessions {
		if session.TenantID != tenantID || session.RevokedAt != nil {
			continue
		}
		if match.ConnectionID != "" && session.ConnectionID != match.ConnectionID {
			continue
		}
		if slices.Contains(match.Subjects, session.Subject) || (session.Email != "" && slices.Contains(match.Emails, strings.ToLower(session.Email))) {
			at := revokedAt
			session.RevokedAt = &at
			s.sessions[k] = session
			count++
		}
	}
	return count, nil
}

func (s *fakeStore) CreateSCIMToken(_ context.Context, token *ports.SCIMToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[key(token.TenantID, token.ID)] = *token
	return nil
}

func (s *fakeStore) ListSCIMTokens(_ context.Context, tenantID string) ([]ports.SCIMToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ports.SCIMToken{}
	for _, token := range s.tokens {
		if token.TenantID == tenantID {
			out = append(out, token)
		}
	}
	return out, nil
}

func (s *fakeStore) GetSCIMTokenByHash(_ context.Context, tenantID string, tokenHash string) (*ports.SCIMToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.tokens {
		if token.TenantID == tenantID && token.TokenHash == tokenHash {
			return &token, nil
		}
	}
	return nil, ports.ErrSCIMTokenNotFound
}

func (s *fakeStore) TouchSCIMToken(_ context.Context, tenantID string, tokenID string, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[key(tenantID, tokenID)]
	if !ok {
		return ports.ErrSCIMTokenNotFound
	}
	token.LastUsedAt = &usedAt
	s.tokens[key(tenantID, tokenID)] = token
	return nil
}

func (s *fakeStore) DeleteSCIMToken(_ context.Context, tenantID string, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[key(tenantID, tokenID)]; !ok {
		return ports.ErrSCIMTokenNotFound
	}
	delete(s.tokens, key(tenantID, tokenID))
	return nil
}

func (s *fakeStore) userGroups(user ports.DirectoryUser) []ports.DirectoryGroupRef {
	refs := []ports.DirectoryGroupRef{}
	for _, group := range s.groups {
		if group.TenantID == user.TenantID && slices.Contains(group.MemberIDs, user.ID) {
			refs = append(refs, ports.DirectoryGroupRef{ID: group.ID, DisplayName: group.DisplayName})
		}
	}
	return refs
}

func (s *fakeStore) ListDirectoryUsers(_ context.Context, query ports.DirectoryUserQuery) ([]ports.DirectoryUser, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	matched := []ports.DirectoryUser{}
	search := strings.ToLower(query.Search)
	for _, user := range s.users {
		switch {
		case user.TenantID != query.TenantID:
		case user.DeletedAt != nil && !query.IncludeDeleted:
		case len(query.IDs) > 0 && !slices.Contains(query.IDs, user.ID):
		case query.Subject != "" && user.Subject != query.Subject:
		case query.ConnectionID != "" && user.ConnectionID != query.ConnectionID:
		case query.UserName != "" && !strings.EqualFold(user.UserName, query.UserName):
		case query.Email != "" && !strings.EqualFold(user.Email, query.Email) && !strings.EqualFold(user.UserName, query.Email):
		case search != "" && !strings.Contains(strings.ToLower(user.UserName+"\x00"+user.Email+"\x00"+user.DisplayName), search):
		default:
			user.Groups = s.userGroups(user)
			matched = append(matched, user)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return strings.ToLower(matched[i].UserName) < strings.ToLower(matched[j].UserName)
	})
	total := len(matched)
	start := min(max(query.Offset, 0), total)
	end := min(start+max(query.Limit, 0), total)
	return matched[start:end], total, nil
}

func (s *fakeStore) GetDirectoryUser(_ context.Context, tenantID string, connectionID string, userID string) (*ports.DirectoryUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key(tenantID, userID)]
	if !ok || user.ConnectionID != connectionID || user.DeletedAt != nil {
		return nil, ports.ErrDirectoryUserNotFound
	}
	user.Groups = s.userGroups(user)
	return &user, nil
}

func (s *fakeStore) userNameTaken(user ports.DirectoryUser) bool {
	for _, other := range s.users {
		if other.TenantID != user.TenantID || other.ConnectionID != user.ConnectionID || other.ID == user.ID {
			continue
		}
		if strings.EqualFold(other.UserName, user.UserName) || (user.Subject != "" && other.Subject == user.Subject) {
			return true
		}
	}
	return false
}

func (s *fakeStore) CreateDirectoryUser(_ context.Context, user *ports.DirectoryUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.userNameTaken(*user) {
		return ports.ErrDirectoryConflict
	}
	stored := *user
	stored.Groups = nil
	s.users[key(user.TenantID, user.ID)] = stored
	return nil
}

func (s *fakeStore) MutateDirectoryUser(_ context.Context, tenantID string, connectionID string, userID string, mutate func(*ports.DirectoryUser) error) (*ports.DirectoryUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key(tenantID, userID)]
	if !ok || user.ConnectionID != connectionID {
		return nil, ports.ErrDirectoryUserNotFound
	}
	user.Groups = s.userGroups(user)
	if err := mutate(&user); err != nil {
		return nil, err
	}
	if s.userNameTaken(user) {
		return nil, ports.ErrDirectoryConflict
	}
	stored := user
	stored.Groups = nil
	s.users[key(tenantID, userID)] = stored
	user.Groups = s.userGroups(user)
	return &user, nil
}

func (s *fakeStore) TombstoneDirectoryUser(_ context.Context, tenantID string, connectionID string, userID string, deletedAt time.Time) (*ports.DirectoryUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[key(tenantID, userID)]
	if !ok || user.ConnectionID != connectionID || user.DeletedAt != nil {
		return nil, ports.ErrDirectoryUserNotFound
	}
	before := user
	before.Groups = s.userGroups(user)
	at := deletedAt
	user.DeletedAt, user.Active, user.UpdatedAt = &at, false, deletedAt
	s.users[key(tenantID, userID)] = user
	for k, group := range s.groups {
		group.MemberIDs = slices.DeleteFunc(group.MemberIDs, func(id string) bool { return id == userID })
		s.groups[k] = group
	}
	return &before, nil
}

func (s *fakeStore) withCount(group ports.DirectoryGroup) ports.DirectoryGroup {
	group.MemberCount = len(group.MemberIDs)
	return group
}

func (s *fakeStore) ListDirectoryGroups(_ context.Context, query ports.DirectoryGroupQuery) ([]ports.DirectoryGroup, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	matched := []ports.DirectoryGroup{}
	for _, group := range s.groups {
		if group.TenantID != query.TenantID || (query.ConnectionID != "" && group.ConnectionID != query.ConnectionID) {
			continue
		}
		if query.DisplayName != "" && !strings.EqualFold(group.DisplayName, query.DisplayName) {
			continue
		}
		matched = append(matched, s.withCount(group))
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].DisplayName < matched[j].DisplayName })
	total := len(matched)
	start := min(max(query.Offset, 0), total)
	end := min(start+max(query.Limit, 0), total)
	return matched[start:end], total, nil
}

func (s *fakeStore) GetDirectoryGroup(_ context.Context, tenantID string, connectionID string, groupID string) (*ports.DirectoryGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.groups[key(tenantID, groupID)]
	if !ok || group.ConnectionID != connectionID {
		return nil, ports.ErrDirectoryGroupNotFound
	}
	group = s.withCount(group)
	return &group, nil
}

func (s *fakeStore) writeGroup(group ports.DirectoryGroup) error {
	for _, other := range s.groups {
		if other.TenantID == group.TenantID && other.ConnectionID == group.ConnectionID && other.ID != group.ID && strings.EqualFold(other.DisplayName, group.DisplayName) {
			return ports.ErrDirectoryConflict
		}
	}
	members := []string{}
	for _, id := range group.MemberIDs {
		if user, ok := s.users[key(group.TenantID, id)]; ok && user.ConnectionID == group.ConnectionID && user.DeletedAt == nil {
			members = append(members, id)
		}
	}
	group.MemberIDs = members
	s.groups[key(group.TenantID, group.ID)] = group
	return nil
}

func (s *fakeStore) CreateDirectoryGroup(_ context.Context, group *ports.DirectoryGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeGroup(*group)
}

func (s *fakeStore) MutateDirectoryGroup(_ context.Context, tenantID string, connectionID string, groupID string, mutate func(*ports.DirectoryGroup) error) (*ports.DirectoryGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.groups[key(tenantID, groupID)]
	if !ok || group.ConnectionID != connectionID {
		return nil, ports.ErrDirectoryGroupNotFound
	}
	group.MemberIDs = slices.Clone(group.MemberIDs)
	if err := mutate(&group); err != nil {
		return nil, err
	}
	if err := s.writeGroup(group); err != nil {
		return nil, err
	}
	stored := s.withCount(s.groups[key(tenantID, groupID)])
	return &stored, nil
}

func (s *fakeStore) DeleteDirectoryGroup(_ context.Context, tenantID string, connectionID string, groupID string) (*ports.DirectoryGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.groups[key(tenantID, groupID)]
	if !ok || group.ConnectionID != connectionID {
		return nil, ports.ErrDirectoryGroupNotFound
	}
	delete(s.groups, key(tenantID, groupID))
	return &group, nil
}

func (s *fakeStore) ConsumeSAMLAssertion(_ context.Context, use ports.SAMLAssertionUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, prior := range s.assertions {
		if prior.TenantID != use.TenantID || !prior.ExpiresAt.After(use.ConsumedAt) {
			continue
		}
		if prior.RequestID == use.RequestID || (prior.ConnectionID == use.ConnectionID && prior.AssertionID == use.AssertionID) {
			return ports.ErrSAMLAssertionReplayed
		}
	}
	s.assertions = append(s.assertions, use)
	return nil
}
