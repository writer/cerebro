package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func (e *SyncEngine) rdsInstanceTable() TableSpec {
	return TableSpec{
		Name:    "aws_rds_instances",
		Columns: []string{"arn", "account_id", "region", "db_instance_identifier", "db_instance_class", "engine", "engine_version", "db_instance_status", "master_username", "endpoint_address", "endpoint_port", "allocated_storage", "storage_type", "storage_encrypted", "kms_key_id", "publicly_accessible", "vpc_security_groups", "db_subnet_group", "multi_az", "auto_minor_version_upgrade", "deletion_protection", "tags"},
		Fetch:   e.fetchRDSInstances,
	}
}

func (e *SyncEngine) fetchRDSInstances(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := rds.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, db := range page.DBInstances {
			var endpointAddr, endpointPort interface{}
			if db.Endpoint != nil {
				endpointAddr = aws.ToString(db.Endpoint.Address)
				endpointPort = db.Endpoint.Port
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                     aws.ToString(db.DBInstanceArn),
				"arn":                        aws.ToString(db.DBInstanceArn),
				"account_id":                 accountID,
				"region":                     region,
				"db_instance_identifier":     aws.ToString(db.DBInstanceIdentifier),
				"db_instance_class":          aws.ToString(db.DBInstanceClass),
				"engine":                     aws.ToString(db.Engine),
				"engine_version":             aws.ToString(db.EngineVersion),
				"db_instance_status":         aws.ToString(db.DBInstanceStatus),
				"master_username":            aws.ToString(db.MasterUsername),
				"endpoint_address":           endpointAddr,
				"endpoint_port":              endpointPort,
				"allocated_storage":          db.AllocatedStorage,
				"storage_type":               aws.ToString(db.StorageType),
				"storage_encrypted":          db.StorageEncrypted,
				"kms_key_id":                 aws.ToString(db.KmsKeyId),
				"publicly_accessible":        db.PubliclyAccessible,
				"vpc_security_groups":        db.VpcSecurityGroups,
				"db_subnet_group":            db.DBSubnetGroup,
				"multi_az":                   db.MultiAZ,
				"auto_minor_version_upgrade": db.AutoMinorVersionUpgrade,
				"deletion_protection":        db.DeletionProtection,
				"tags":                       db.TagList,
			})
		}
	}
	return rows, nil
}
