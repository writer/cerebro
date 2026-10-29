package cloudidentitysource

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// awsAssumedConfig caches one member account's assumed-role aws.Config for
// the lifetime of a reader (one collection run); it is never persisted and
// never logged.
type awsAssumedConfig struct {
	config    aws.Config
	expiresAt time.Time
}

// awsAssumeRoleARN builds the scan role ARN for a member account.
func awsAssumeRoleARN(account, roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", account, roleName)
}

// awsClampDurationSeconds converts a configured role duration to the
// int32 seconds value STS expects, clamping to math.MaxInt32 rather than
// risking a silent overflow wraparound for a pathologically large configured
// duration (STS itself rejects anything above its own much smaller max).
func awsClampDurationSeconds(d time.Duration) int32 {
	seconds := d / time.Second
	if seconds > math.MaxInt32 {
		return math.MaxInt32
	}
	if seconds < 0 {
		return 0
	}
	return int32(seconds) //nolint:gosec // bounds checked explicitly above; seconds is in [0, math.MaxInt32] here.
}

// assumedConfig returns a cached or freshly assumed aws.Config scoped to
// options.RoleName in account. Credentials are cached in-memory for this
// reader's lifetime only (bounded by AssumeRoleDuration), never written to
// disk or logs.
func (r *awsReader) assumedConfig(ctx context.Context, account string) (aws.Config, error) {
	r.assumeMu.Lock()
	if cached, ok := r.assumed[account]; ok && r.clock().Before(cached.expiresAt) {
		r.assumeMu.Unlock()
		return cached.config, nil
	}
	r.assumeMu.Unlock()

	if err := r.budget.take(); err != nil {
		return aws.Config{}, err
	}
	roleARN := awsAssumeRoleARN(account, r.options.RoleName)
	stsClient := r.options.STSClientFactory(r.options.Config)
	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(r.options.SessionName),
	}
	if r.options.ExternalID != "" {
		input.ExternalId = aws.String(r.options.ExternalID)
	}
	durationSeconds := awsClampDurationSeconds(r.options.AssumeRoleDuration)
	if durationSeconds > 0 {
		input.DurationSeconds = aws.Int32(durationSeconds)
	}
	out, err := stsClient.AssumeRole(ctx, input)
	if err != nil {
		return aws.Config{}, fmt.Errorf("assume role %s: %w", roleARN, err)
	}
	if out.Credentials == nil {
		return aws.Config{}, fmt.Errorf("assume role %s: no credentials returned", roleARN)
	}
	creds := out.Credentials
	expiresAt := r.clock().Add(r.options.AssumeRoleDuration)
	if creds.Expiration != nil && creds.Expiration.Before(expiresAt) {
		expiresAt = *creds.Expiration
	}
	assumed := aws.Config{
		Region: r.region(),
		Credentials: aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     aws.ToString(creds.AccessKeyId),
				SecretAccessKey: aws.ToString(creds.SecretAccessKey),
				SessionToken:    aws.ToString(creds.SessionToken),
				CanExpire:       creds.Expiration != nil,
				Expires:         aws.ToTime(creds.Expiration),
				Source:          "cloudidentitysource.awsReader.assumedConfig",
			}, nil
		})),
	}
	r.assumeMu.Lock()
	r.assumed[account] = awsAssumedConfig{config: assumed, expiresAt: expiresAt}
	r.assumeMu.Unlock()
	return assumed, nil
}

// assumedConfigForRegion returns the same assumed-role credentials as
// assumedConfig, scoped to account, but with Region overridden to region
// instead of the reader-wide default. EKS clusters/Pod Identity
// associations are regional: each scanned target carries its own cluster
// location (Workload.Region), so a single per-account cached config is
// insufficient and would silently route EKS reads to the wrong region. This
// issues no extra sts:AssumeRole call; it reuses (or populates) the same
// per-account credential cache and only clones the Region field.
func (r *awsReader) assumedConfigForRegion(ctx context.Context, account string, region string) (aws.Config, error) {
	cfg, err := r.assumedConfig(ctx, account)
	if err != nil {
		return aws.Config{}, err
	}
	cfg.Region = region
	return cfg, nil
}
