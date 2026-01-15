package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type QueueMessage struct {
	ID            string
	ReceiptHandle string
	Body          string
}

type Queue interface {
	Enqueue(ctx context.Context, msg JobMessage) error
	Receive(ctx context.Context, maxMessages int, waitTime time.Duration, visibilityTimeout time.Duration) ([]QueueMessage, error)
	Delete(ctx context.Context, receiptHandle string) error
}

type SQSQueue struct {
	client   *sqs.Client
	queueURL string
}

func NewSQSQueue(cfg aws.Config, queueURL string) *SQSQueue {
	return &SQSQueue{
		client:   sqs.NewFromConfig(cfg),
		queueURL: queueURL,
	}
}

func (q *SQSQueue) Enqueue(ctx context.Context, msg JobMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = q.client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    aws.String(q.queueURL),
		MessageBody: aws.String(string(body)),
	})
	return err
}

func (q *SQSQueue) Receive(ctx context.Context, maxMessages int, waitTime time.Duration, visibilityTimeout time.Duration) ([]QueueMessage, error) {
	if maxMessages <= 0 {
		maxMessages = 1
	}
	if maxMessages > 10 {
		maxMessages = 10
	}

	input := &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(q.queueURL),
		MaxNumberOfMessages: int32(maxMessages),
		WaitTimeSeconds:     int32(waitTime.Seconds()),
	}
	if visibilityTimeout > 0 {
		input.VisibilityTimeout = int32(visibilityTimeout.Seconds())
	}

	out, err := q.client.ReceiveMessage(ctx, input)
	if err != nil {
		return nil, err
	}

	msgs := make([]QueueMessage, 0, len(out.Messages))
	for _, msg := range out.Messages {
		if msg.ReceiptHandle == nil || msg.Body == nil {
			continue
		}
		id := ""
		if msg.MessageId != nil {
			id = *msg.MessageId
		}
		msgs = append(msgs, QueueMessage{
			ID:            id,
			ReceiptHandle: *msg.ReceiptHandle,
			Body:          *msg.Body,
		})
	}

	return msgs, nil
}

func (q *SQSQueue) Delete(ctx context.Context, receiptHandle string) error {
	if receiptHandle == "" {
		return fmt.Errorf("receipt handle required")
	}
	_, err := q.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(q.queueURL),
		ReceiptHandle: aws.String(receiptHandle),
	})
	return err
}
