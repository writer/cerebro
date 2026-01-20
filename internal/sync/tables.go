package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// TableSpec defines a table to sync
type TableSpec struct {
	Name    string
	Columns []string
	Fetch   func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error)
}

// SyncResult holds results for a single table sync
type SyncResult struct {
	Table    string
	Region   string
	Synced   int
	Errors   int
	Duration time.Duration
	Changes  *ChangeSet
}

// ChangeSet tracks what changed during sync
type ChangeSet struct {
	Added    []string
	Removed  []string
	Modified []string
}

func (c *ChangeSet) HasChanges() bool {
	if c == nil {
		return false
	}
	return len(c.Added) > 0 || len(c.Removed) > 0 || len(c.Modified) > 0
}

func (c *ChangeSet) Summary() string {
	if c == nil {
		return "+0/~0/-0"
	}
	return fmt.Sprintf("+%d/~%d/-%d", len(c.Added), len(c.Modified), len(c.Removed))
}

// getAWSTables returns all AWS table definitions
func (e *SyncEngine) getAWSTables() []TableSpec {
	return []TableSpec{
		// ECS
		e.ecsClusterTable(),
		e.ecsServiceTable(),
		e.ecsTaskDefinitionTable(),
		// EC2
		e.ec2InstanceTable(),
		e.ec2SecurityGroupTable(),
		e.ec2VPCTable(),
		// IAM
		e.iamRoleTable(),
		e.iamUserTable(),
		e.iamCredentialReportTable(),
		// Storage
		e.s3BucketTable(),
		e.ecrRepositoryTable(),
		// Compute
		e.lambdaFunctionTable(),
		// Security
		e.kmsKeyTable(),
		e.secretsManagerSecretTable(),
		// Database
		e.rdsInstanceTable(),
	}
}

func (e *SyncEngine) getAccountIDFromConfig(ctx context.Context, cfg aws.Config) string {
	if e.accountID != "" {
		return e.accountID
	}
	stsClient := sts.NewFromConfig(cfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err == nil && out.Account != nil {
		e.accountID = *out.Account
	}
	return e.accountID
}
