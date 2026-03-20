package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

const DefaultStoreNamespace = executionstore.NamespaceIdentityAccessReview

type Store interface {
	SaveReview(context.Context, *AccessReview) error
	LoadReview(context.Context, string) (*AccessReview, error)
	ListReviews(context.Context, ReviewStatus) ([]*AccessReview, error)
	AppendEvent(context.Context, string, ReviewEvent) (ReviewEvent, error)
	LoadEvents(context.Context, string) ([]ReviewEvent, error)
	Close() error
}

type MemoryStore struct {
	mu      sync.RWMutex
	reviews map[string]*AccessReview
	events  map[string][]ReviewEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		reviews: make(map[string]*AccessReview),
		events:  make(map[string][]ReviewEvent),
	}
}

func (s *MemoryStore) SaveReview(_ context.Context, review *AccessReview) error {
	if s == nil || review == nil {
		return nil
	}
	cloned, err := cloneAccessReview(review)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reviews[review.ID] = cloned
	return nil
}

func (s *MemoryStore) LoadReview(_ context.Context, reviewID string) (*AccessReview, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	review := s.reviews[strings.TrimSpace(reviewID)]
	if review == nil {
		return nil, nil
	}
	cloned, err := cloneAccessReview(review)
	if err != nil {
		return nil, err
	}
	if events, ok := s.events[review.ID]; ok {
		cloned.Events = cloneReviewEvents(events)
	}
	return cloned, nil
}

func (s *MemoryStore) ListReviews(_ context.Context, status ReviewStatus) ([]*AccessReview, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	reviews := make([]*AccessReview, 0, len(s.reviews))
	for _, review := range s.reviews {
		if status != "" && review.Status != status {
			continue
		}
		cloned, err := cloneAccessReview(review)
		if err != nil {
			return nil, err
		}
		reviews = append(reviews, cloned)
	}
	sort.Slice(reviews, func(i, j int) bool {
		return reviews[i].CreatedAt.After(reviews[j].CreatedAt)
	})
	return reviews, nil
}

func (s *MemoryStore) AppendEvent(_ context.Context, reviewID string, event ReviewEvent) (ReviewEvent, error) {
	if s == nil {
		return event, nil
	}
	reviewID = strings.TrimSpace(reviewID)
	if event.RecordedAt.IsZero() {
		event.RecordedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event.Sequence = int64(len(s.events[reviewID]) + 1)
	s.events[reviewID] = append(s.events[reviewID], event)
	return event, nil
}

func (s *MemoryStore) LoadEvents(_ context.Context, reviewID string) ([]ReviewEvent, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneReviewEvents(s.events[strings.TrimSpace(reviewID)]), nil
}

func (s *MemoryStore) Close() error { return nil }

type SQLiteStore struct {
	store     executionstore.Store
	namespace string
	ownsStore bool
}

func NewSQLiteStore(path string, namespace string) (*SQLiteStore, error) {
	store, err := executionstore.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	sqliteStore := NewSQLiteStoreWithExecutionStore(store, namespace)
	sqliteStore.ownsStore = true
	return sqliteStore, nil
}

func NewSQLiteStoreWithExecutionStore(store executionstore.Store, namespace string) *SQLiteStore {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = DefaultStoreNamespace
	}
	return &SQLiteStore{store: store, namespace: namespace}
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.store == nil || !s.ownsStore {
		return nil
	}
	return s.store.Close()
}

func (s *SQLiteStore) SaveReview(ctx context.Context, review *AccessReview) error {
	if s == nil || s.store == nil || review == nil {
		return nil
	}
	payload, err := json.Marshal(reviewWithoutEvents(review))
	if err != nil {
		return fmt.Errorf("marshal access review: %w", err)
	}
	return s.store.UpsertRun(ctx, executionstore.RunEnvelope{
		Namespace:   s.namespace,
		RunID:       strings.TrimSpace(review.ID),
		Kind:        "access_review",
		Status:      string(review.Status),
		Stage:       reviewStage(review.Status),
		SubmittedAt: review.CreatedAt.UTC(),
		StartedAt:   review.StartedAt,
		CompletedAt: review.CompletedAt,
		UpdatedAt:   reviewUpdatedAt(review),
		Payload:     payload,
	})
}

func (s *SQLiteStore) LoadReview(ctx context.Context, reviewID string) (*AccessReview, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	env, err := s.store.LoadRun(ctx, s.namespace, strings.TrimSpace(reviewID))
	if err != nil || env == nil {
		return nil, err
	}
	var review AccessReview
	if err := json.Unmarshal(env.Payload, &review); err != nil {
		return nil, fmt.Errorf("unmarshal access review: %w", err)
	}
	events, err := s.LoadEvents(ctx, review.ID)
	if err != nil {
		return nil, err
	}
	review.Events = events
	return &review, nil
}

func (s *SQLiteStore) ListReviews(ctx context.Context, status ReviewStatus) ([]*AccessReview, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	opts := executionstore.RunListOptions{OrderBySubmittedAt: true}
	if status != "" {
		opts.Statuses = []string{string(status)}
	}
	envs, err := s.store.ListRuns(ctx, s.namespace, opts)
	if err != nil {
		return nil, err
	}
	reviews := make([]*AccessReview, 0, len(envs))
	for _, env := range envs {
		var review AccessReview
		if err := json.Unmarshal(env.Payload, &review); err != nil {
			return nil, fmt.Errorf("unmarshal access review list item: %w", err)
		}
		reviews = append(reviews, &review)
	}
	return reviews, nil
}

func (s *SQLiteStore) AppendEvent(ctx context.Context, reviewID string, event ReviewEvent) (ReviewEvent, error) {
	if s == nil || s.store == nil {
		return event, nil
	}
	if event.RecordedAt.IsZero() {
		event.RecordedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return event, fmt.Errorf("marshal access review event: %w", err)
	}
	env, err := s.store.SaveEvent(ctx, executionstore.EventEnvelope{
		Namespace:  s.namespace,
		RunID:      strings.TrimSpace(reviewID),
		RecordedAt: event.RecordedAt.UTC(),
		Payload:    payload,
	})
	if err != nil {
		return event, err
	}
	event.Sequence = env.Sequence
	event.RecordedAt = env.RecordedAt
	return event, nil
}

func (s *SQLiteStore) LoadEvents(ctx context.Context, reviewID string) ([]ReviewEvent, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	envs, err := s.store.LoadEvents(ctx, s.namespace, strings.TrimSpace(reviewID))
	if err != nil {
		return nil, err
	}
	events := make([]ReviewEvent, 0, len(envs))
	for _, env := range envs {
		var event ReviewEvent
		if err := json.Unmarshal(env.Payload, &event); err != nil {
			return nil, fmt.Errorf("unmarshal access review event: %w", err)
		}
		event.Sequence = env.Sequence
		event.RecordedAt = env.RecordedAt
		events = append(events, event)
	}
	return events, nil
}

func reviewStage(status ReviewStatus) string {
	switch status {
	case ReviewStatusScheduled:
		return "scheduled"
	case ReviewStatusInProgress:
		return "active"
	case ReviewStatusCompleted, ReviewStatusCanceled:
		return "completed"
	default:
		return "draft"
	}
}

func reviewUpdatedAt(review *AccessReview) time.Time {
	if review == nil {
		return time.Now().UTC()
	}
	if review.CompletedAt != nil && !review.CompletedAt.IsZero() {
		return review.CompletedAt.UTC()
	}
	if review.StartedAt != nil && !review.StartedAt.IsZero() {
		return review.StartedAt.UTC()
	}
	return review.CreatedAt.UTC()
}

func reviewWithoutEvents(review *AccessReview) *AccessReview {
	if review == nil {
		return nil
	}
	copy := *review
	copy.Events = nil
	return &copy
}

func cloneAccessReview(review *AccessReview) (*AccessReview, error) {
	if review == nil {
		return nil, nil
	}
	payload, err := json.Marshal(review)
	if err != nil {
		return nil, fmt.Errorf("clone access review: %w", err)
	}
	var cloned AccessReview
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return nil, fmt.Errorf("clone access review: %w", err)
	}
	return &cloned, nil
}

func cloneReviewEvents(events []ReviewEvent) []ReviewEvent {
	if len(events) == 0 {
		return nil
	}
	payload, err := json.Marshal(events)
	if err != nil {
		out := make([]ReviewEvent, len(events))
		copy(out, events)
		return out
	}
	var cloned []ReviewEvent
	if err := json.Unmarshal(payload, &cloned); err != nil {
		out := make([]ReviewEvent, len(events))
		copy(out, events)
		return out
	}
	return cloned
}
