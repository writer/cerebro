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

type Store interface {
	CreateJob(ctx context.Context, job *Job) error
	GetJob(ctx context.Context, jobID string) (*Job, error)
	ClaimJob(ctx context.Context, jobID, workerID string, lease time.Duration) (*Job, bool, error)
	ExtendLease(ctx context.Context, jobID, workerID string, lease time.Duration) error
	CompleteJob(ctx context.Context, jobID, result string) error
	FailJob(ctx context.Context, jobID, message string) error
	RetryJob(ctx context.Context, jobID, message string) error
	CompleteJobOwned(ctx context.Context, jobID, workerID string, attempt int, result string) error
	FailJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error
	RetryJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error
}

var ErrJobLeaseLost = errors.New("job lease lost")

type DynamoStore struct {
	client *dynamodb.Client
	table  string
}

func NewDynamoStore(cfg aws.Config, table string) *DynamoStore {
	return &DynamoStore{
		client: dynamodb.NewFromConfig(cfg),
		table:  table,
	}
}

func (s *DynamoStore) CreateJob(ctx context.Context, job *Job) error {
	if job == nil {
		return fmt.Errorf("job required")
	}

	item, err := attributevalue.MarshalMap(job)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(job_id)"),
	})
	return err
}

func (s *DynamoStore) GetJob(ctx context.Context, jobID string) (*Job, error) {
	if jobID == "" {
		return nil, fmt.Errorf("job id required")
	}

	resp, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Item) == 0 {
		return nil, fmt.Errorf("job not found")
	}

	var job Job
	if err := attributevalue.UnmarshalMap(resp.Item, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *DynamoStore) ClaimJob(ctx context.Context, jobID, workerID string, lease time.Duration) (*Job, bool, error) {
	if jobID == "" {
		return nil, false, fmt.Errorf("job id required")
	}
	if workerID == "" {
		return nil, false, fmt.Errorf("worker id required")
	}

	now := time.Now().UTC().Unix()
	leaseUntil := now + int64(lease.Seconds())

	output, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression:    aws.String("SET #status = :running, worker_id = :worker, lease_expires_at = :lease, updated_at = :now ADD attempt :one"),
		ConditionExpression: aws.String("#status = :queued OR (#status = :running AND lease_expires_at < :now)"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":queued":  &types.AttributeValueMemberS{Value: string(StatusQueued)},
			":running": &types.AttributeValueMemberS{Value: string(StatusRunning)},
			":worker":  &types.AttributeValueMemberS{Value: workerID},
			":lease":   &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", leaseUntil)},
			":now":     &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":one":     &types.AttributeValueMemberN{Value: "1"},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		var conditional *types.ConditionalCheckFailedException
		if errors.As(err, &conditional) {
			return nil, false, nil
		}
		return nil, false, err
	}

	var job Job
	if err := attributevalue.UnmarshalMap(output.Attributes, &job); err != nil {
		return nil, false, err
	}

	return &job, true, nil
}

func (s *DynamoStore) ExtendLease(ctx context.Context, jobID, workerID string, lease time.Duration) error {
	if jobID == "" {
		return fmt.Errorf("job id required")
	}
	if workerID == "" {
		return fmt.Errorf("worker id required")
	}

	now := time.Now().UTC().Unix()
	leaseUntil := now + int64(lease.Seconds())

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression:    aws.String("SET lease_expires_at = :lease, updated_at = :now"),
		ConditionExpression: aws.String("#status = :running AND worker_id = :worker"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":running": &types.AttributeValueMemberS{Value: string(StatusRunning)},
			":worker":  &types.AttributeValueMemberS{Value: workerID},
			":lease":   &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", leaseUntil)},
			":now":     &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
		},
	})
	if err != nil {
		var conditional *types.ConditionalCheckFailedException
		if errors.As(err, &conditional) {
			return ErrJobLeaseLost
		}
		return err
	}
	return nil
}

func (s *DynamoStore) CompleteJob(ctx context.Context, jobID, result string) error {
	now := time.Now().UTC().Unix()
	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression: aws.String("SET #status = :status, #result = :result, #error = :error, updated_at = :now, lease_expires_at = :zero"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
			"#result": "result",
			"#error":  "error",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: string(StatusSucceeded)},
			":result": &types.AttributeValueMemberS{Value: result},
			":error":  &types.AttributeValueMemberS{Value: ""},
			":now":    &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":zero":   &types.AttributeValueMemberN{Value: "0"},
		},
	})
	return err
}

func (s *DynamoStore) CompleteJobOwned(ctx context.Context, jobID, workerID string, attempt int, result string) error {
	now := time.Now().UTC().Unix()
	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression:    aws.String("SET #status = :status, #result = :result, #error = :error, updated_at = :now, lease_expires_at = :zero"),
		ConditionExpression: aws.String("#status = :running AND worker_id = :worker AND attempt = :attempt"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
			"#result": "result",
			"#error":  "error",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":  &types.AttributeValueMemberS{Value: string(StatusSucceeded)},
			":running": &types.AttributeValueMemberS{Value: string(StatusRunning)},
			":worker":  &types.AttributeValueMemberS{Value: workerID},
			":attempt": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", attempt)},
			":result":  &types.AttributeValueMemberS{Value: result},
			":error":   &types.AttributeValueMemberS{Value: ""},
			":now":     &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":zero":    &types.AttributeValueMemberN{Value: "0"},
		},
	})
	if err != nil {
		var conditional *types.ConditionalCheckFailedException
		if errors.As(err, &conditional) {
			return ErrJobLeaseLost
		}
	}
	return err
}

func (s *DynamoStore) FailJob(ctx context.Context, jobID, message string) error {
	now := time.Now().UTC().Unix()
	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression: aws.String("SET #status = :status, #error = :error, updated_at = :now, lease_expires_at = :zero"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
			"#error":  "error",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: string(StatusFailed)},
			":error":  &types.AttributeValueMemberS{Value: message},
			":now":    &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":zero":   &types.AttributeValueMemberN{Value: "0"},
		},
	})
	return err
}

func (s *DynamoStore) FailJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error {
	now := time.Now().UTC().Unix()
	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression:    aws.String("SET #status = :status, #error = :error, updated_at = :now, lease_expires_at = :zero"),
		ConditionExpression: aws.String("#status = :running AND worker_id = :worker AND attempt = :attempt"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
			"#error":  "error",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":  &types.AttributeValueMemberS{Value: string(StatusFailed)},
			":running": &types.AttributeValueMemberS{Value: string(StatusRunning)},
			":worker":  &types.AttributeValueMemberS{Value: workerID},
			":attempt": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", attempt)},
			":error":   &types.AttributeValueMemberS{Value: message},
			":now":     &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":zero":    &types.AttributeValueMemberN{Value: "0"},
		},
	})
	if err != nil {
		var conditional *types.ConditionalCheckFailedException
		if errors.As(err, &conditional) {
			return ErrJobLeaseLost
		}
	}
	return err
}

func (s *DynamoStore) RetryJob(ctx context.Context, jobID, message string) error {
	now := time.Now().UTC().Unix()
	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression: aws.String("SET #status = :status, #error = :error, updated_at = :now, lease_expires_at = :zero, worker_id = :worker"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
			"#error":  "error",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: string(StatusQueued)},
			":error":  &types.AttributeValueMemberS{Value: message},
			":now":    &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":zero":   &types.AttributeValueMemberN{Value: "0"},
			":worker": &types.AttributeValueMemberS{Value: ""},
		},
	})
	return err
}

func (s *DynamoStore) RetryJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error {
	now := time.Now().UTC().Unix()
	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"job_id": &types.AttributeValueMemberS{Value: jobID},
		},
		UpdateExpression:    aws.String("SET #status = :status, #error = :error, updated_at = :now, lease_expires_at = :zero, worker_id = :next_worker"),
		ConditionExpression: aws.String("#status = :running AND worker_id = :worker AND attempt = :attempt"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
			"#error":  "error",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":      &types.AttributeValueMemberS{Value: string(StatusQueued)},
			":running":     &types.AttributeValueMemberS{Value: string(StatusRunning)},
			":worker":      &types.AttributeValueMemberS{Value: workerID},
			":attempt":     &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", attempt)},
			":error":       &types.AttributeValueMemberS{Value: message},
			":now":         &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)},
			":zero":        &types.AttributeValueMemberN{Value: "0"},
			":next_worker": &types.AttributeValueMemberS{Value: ""},
		},
	})
	if err != nil {
		var conditional *types.ConditionalCheckFailedException
		if errors.As(err, &conditional) {
			return ErrJobLeaseLost
		}
	}
	return err
}
