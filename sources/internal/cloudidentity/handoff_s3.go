package cloudidentitysource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/writer/cerebro/internal/buildinfo"
)

func cerebroBuildVersion() string {
	return buildinfo.Version
}

// s3PutAPI is the narrow S3 surface the evidence handoff publisher needs:
// a single conditional PutObject call. No List/Get/Delete capability is
// ever requested, matching the intake bucket policy's
// s3:PutObject-only grant.
type s3PutAPI interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// s3HandoffPublisher implements HandoffPublisher against a real S3 bucket.
type s3HandoffPublisher struct {
	client s3PutAPI
}

// newS3HandoffPublisher constructs the real AWS SDK v2 adapter using the
// ambient runtime credentials (the deployed task's own role, which the
// VulnView-owned intake bucket policy grants s3:PutObject on its own
// cloud-identity/<stream>/* prefix). It performs no role assumption of its
// own: the bucket policy, not this source, decides which deployed
// environment may publish which stream.
func newS3HandoffPublisher(ctx context.Context, region string) (HandoffPublisher, error) {
	region = strings.TrimSpace(region)
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config for evidence handoff: %w", err)
	}
	return &s3HandoffPublisher{client: s3.NewFromConfig(cfg)}, nil
}

// Publish writes body to bucket/key with a conditional create
// (If-None-Match: "*"). A precondition-failed response means this exact
// content-addressed key already exists and is treated as success: the
// bundle for this collection pass was already durably published, whether
// by this run or an earlier retry.
func (p *s3HandoffPublisher) Publish(ctx context.Context, bucket, region, key string, body []byte) error {
	_ = region // resolved once at construction; kept on the interface for fakes/tests that assert on it.
	_, err := p.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          awssdk.String(bucket),
		Key:             awssdk.String(key),
		Body:            bytes.NewReader(body),
		ContentType:     awssdk.String("application/json"),
		ContentEncoding: awssdk.String("gzip"),
		IfNoneMatch:     awssdk.String("*"),
	})
	if err == nil {
		return nil
	}
	if isPreconditionFailed(err) {
		return nil
	}
	return err
}

// isPreconditionFailed reports whether err is an HTTP 412 response, the
// status the intake bucket's conditional-write policy returns when
// If-None-Match already matches an existing object.
func isPreconditionFailed(err error) bool {
	var responseErr *smithyhttp.ResponseError
	return errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == 412
}
