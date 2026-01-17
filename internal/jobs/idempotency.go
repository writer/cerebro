package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// IdempotencyStore tracks processed message IDs to prevent duplicate processing.
// Uses DynamoDB with TTL for automatic cleanup.
type IdempotencyStore interface {
	// MarkProcessing attempts to mark a message as being processed.
	// Returns true if this is the first time seeing this message.
	// Returns false if the message was already processed or is being processed.
	MarkProcessing(ctx context.Context, messageID string, workerID string, ttl time.Duration) (bool, error)

	// MarkCompleted marks a message as successfully processed.
	MarkCompleted(ctx context.Context, messageID string) error

	// MarkFailed removes the processing lock so the message can be retried.
	MarkFailed(ctx context.Context, messageID string) error

	// IsProcessed checks if a message was already successfully processed.
	IsProcessed(ctx context.Context, messageID string) (bool, error)
}

// IdempotencyRecord represents a processed message record.
type IdempotencyRecord struct {
	MessageID   string `dynamodbav:"message_id"`
	Status      string `dynamodbav:"status"` // "processing", "completed"
	WorkerID    string `dynamodbav:"worker_id"`
	ProcessedAt int64  `dynamodbav:"processed_at"`
	ExpiresAt   int64  `dynamodbav:"expires_at"` // TTL attribute
}

const (
	idempotencyStatusProcessing = "processing"
	idempotencyStatusCompleted  = "completed"
)

// DynamoIdempotencyStore implements IdempotencyStore using DynamoDB.
type DynamoIdempotencyStore struct {
	client *dynamodb.Client
	table  string
}

// NewDynamoIdempotencyStore creates a new DynamoDB-backed idempotency store.
// The table should have:
// - Partition key: message_id (String)
// - TTL attribute: expires_at
func NewDynamoIdempotencyStore(cfg aws.Config, table string) *DynamoIdempotencyStore {
	return &DynamoIdempotencyStore{
		client: dynamodb.NewFromConfig(cfg),
		table:  table,
	}
}

func (s *DynamoIdempotencyStore) MarkProcessing(ctx context.Context, messageID string, workerID string, ttl time.Duration) (bool, error) {
	if messageID == "" {
		return false, fmt.Errorf("message ID required")
	}

	now := time.Now().UTC().Unix()
	expiresAt := now + int64(ttl.Seconds())

	record := IdempotencyRecord{
		MessageID:   messageID,
		Status:      idempotencyStatusProcessing,
		WorkerID:    workerID,
		ProcessedAt: now,
		ExpiresAt:   expiresAt,
	}

	item, err := attributevalue.MarshalMap(record)
	if err != nil {
		return false, err
	}

	// Conditional put - only succeeds if:
	// 1. Record doesn't exist, OR
	// 2. Record exists but status is not "completed" and has expired
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(message_id) OR (#status <> :completed AND expires_at < :now)"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":completed": &types.AttributeValueMemberS{Value: idempotencyStatusCompleted},
			":now":       &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
		},
	})

	if err != nil {
		// Check if it's a conditional check failure (already processed/processing)
		var ccf *types.ConditionalCheckFailedException
		if ok := isConditionalCheckFailed(err, &ccf); ok {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (s *DynamoIdempotencyStore) MarkCompleted(ctx context.Context, messageID string) error {
	if messageID == "" {
		return fmt.Errorf("message ID required")
	}

	now := time.Now().UTC().Unix()
	// Keep completed records for 24 hours for debugging
	expiresAt := now + 24*60*60

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"message_id": &types.AttributeValueMemberS{Value: messageID},
		},
		UpdateExpression: aws.String("SET #status = :completed, processed_at = :now, expires_at = :expires"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":completed": &types.AttributeValueMemberS{Value: idempotencyStatusCompleted},
			":now":       &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":expires":   &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiresAt)},
		},
	})
	return err
}

func (s *DynamoIdempotencyStore) MarkFailed(ctx context.Context, messageID string) error {
	if messageID == "" {
		return fmt.Errorf("message ID required")
	}

	// Delete the record so it can be retried
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"message_id": &types.AttributeValueMemberS{Value: messageID},
		},
	})
	return err
}

func (s *DynamoIdempotencyStore) IsProcessed(ctx context.Context, messageID string) (bool, error) {
	if messageID == "" {
		return false, fmt.Errorf("message ID required")
	}

	resp, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"message_id": &types.AttributeValueMemberS{Value: messageID},
		},
		ProjectionExpression: aws.String("#status"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
	})
	if err != nil {
		return false, err
	}

	if len(resp.Item) == 0 {
		return false, nil
	}

	var record IdempotencyRecord
	if err := attributevalue.UnmarshalMap(resp.Item, &record); err != nil {
		return false, err
	}

	return record.Status == idempotencyStatusCompleted, nil
}

// NoOpIdempotencyStore is a no-op implementation for testing or when idempotency is disabled.
type NoOpIdempotencyStore struct{}

func (s *NoOpIdempotencyStore) MarkProcessing(ctx context.Context, messageID string, workerID string, ttl time.Duration) (bool, error) {
	return true, nil
}
func (s *NoOpIdempotencyStore) MarkCompleted(ctx context.Context, messageID string) error {
	return nil
}
func (s *NoOpIdempotencyStore) MarkFailed(ctx context.Context, messageID string) error {
	return nil
}
func (s *NoOpIdempotencyStore) IsProcessed(ctx context.Context, messageID string) (bool, error) {
	return false, nil
}

// Helper to check for conditional check failure
func isConditionalCheckFailed(err error, target **types.ConditionalCheckFailedException) bool {
	var ccf *types.ConditionalCheckFailedException
	if ok := errors.As(err, &ccf); ok {
		if target != nil {
			*target = ccf
		}
		return true
	}
	return false
}
