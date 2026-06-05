package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsRedshiftCluster struct {
	Cluster redshifttypes.Cluster
	Tags    map[string]string
}

type awsDocDBCluster struct {
	Cluster docdbtypes.DBCluster
	Tags    map[string]string
}

type awsDocDBInstance struct {
	Instance docdbtypes.DBInstance
	Tags     map[string]string
}

type awsNeptuneCluster struct {
	Cluster neptunetypes.DBCluster
	Tags    map[string]string
}

type awsNeptuneInstance struct {
	Instance neptunetypes.DBInstance
	Tags     map[string]string
}

func listRedshiftClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsRedshiftCluster, string, error) {
	out, err := clients.redshift.DescribeClusters(ctx, &redshift.DescribeClustersInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsRedshiftCluster, 0, len(out.Clusters))
	for _, cluster := range out.Clusters {
		records = append(records, awsRedshiftCluster{Cluster: cluster, Tags: redshiftTagMap(cluster.Tags)})
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listDocDBClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsDocDBCluster, string, error) {
	out, err := clients.docdb.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDocDBCluster, 0, len(out.DBClusters))
	for _, cluster := range out.DBClusters {
		record := awsDocDBCluster{Cluster: cluster}
		if arn := awssdk.ToString(cluster.DBClusterArn); arn != "" {
			tags, err := clients.docdb.ListTagsForResource(ctx, &docdb.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list documentdb cluster tags %q: %w", arn, err)
			}
			record.Tags = docDBTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listDocDBInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsDocDBInstance, string, error) {
	out, err := clients.docdb.DescribeDBInstances(ctx, &docdb.DescribeDBInstancesInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsDocDBInstance, 0, len(out.DBInstances))
	for _, instance := range out.DBInstances {
		record := awsDocDBInstance{Instance: instance}
		if arn := awssdk.ToString(instance.DBInstanceArn); arn != "" {
			tags, err := clients.docdb.ListTagsForResource(ctx, &docdb.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list documentdb instance tags %q: %w", arn, err)
			}
			record.Tags = docDBTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listNeptuneClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsNeptuneCluster, string, error) {
	out, err := clients.neptune.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsNeptuneCluster, 0, len(out.DBClusters))
	for _, cluster := range out.DBClusters {
		record := awsNeptuneCluster{Cluster: cluster}
		if arn := awssdk.ToString(cluster.DBClusterArn); arn != "" {
			tags, err := clients.neptune.ListTagsForResource(ctx, &neptune.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list neptune cluster tags %q: %w", arn, err)
			}
			record.Tags = neptuneTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listNeptuneInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsNeptuneInstance, string, error) {
	out, err := clients.neptune.DescribeDBInstances(ctx, &neptune.DescribeDBInstancesInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 20, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsNeptuneInstance, 0, len(out.DBInstances))
	for _, instance := range out.DBInstances {
		record := awsNeptuneInstance{Instance: instance}
		if arn := awssdk.ToString(instance.DBInstanceArn); arn != "" {
			tags, err := clients.neptune.ListTagsForResource(ctx, &neptune.ListTagsForResourceInput{ResourceName: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list neptune instance tags %q: %w", arn, err)
			}
			record.Tags = neptuneTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.Marker), nil
}

func redshiftClusterEvent(settings settings, record awsRedshiftCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	name := awssdk.ToString(cluster.ClusterIdentifier)
	arn := redshiftClusterARN(settings, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyRedshiftCluster, firstNonEmpty(arn, name), name, "redshift_cluster", record.Tags)
	attributes["arn"] = arn
	attributes["allow_version_upgrade"] = boolString(awssdk.ToBool(cluster.AllowVersionUpgrade))
	attributes["availability_zone"] = awssdk.ToString(cluster.AvailabilityZone)
	attributes["cluster_identifier"] = name
	attributes["cluster_version"] = awssdk.ToString(cluster.ClusterVersion)
	attributes["encryption"] = boolString(awssdk.ToBool(cluster.Encrypted))
	attributes["enhanced_vpc_routing"] = boolString(awssdk.ToBool(cluster.EnhancedVpcRouting))
	attributes["engine"] = "redshift"
	attributes["internet_exposed"] = boolString(awssdk.ToBool(cluster.PubliclyAccessible))
	attributes["kms_key_id"] = awssdk.ToString(cluster.KmsKeyId)
	attributes["node_type"] = awssdk.ToString(cluster.NodeType)
	attributes["number_of_nodes"] = int32AttrString(cluster.NumberOfNodes)
	attributes["public"] = boolString(awssdk.ToBool(cluster.PubliclyAccessible))
	attributes["role_arn"] = strings.Join(redshiftRoleARNs(cluster.IamRoles), ",")
	attributes["security_group_ids"] = strings.Join(redshiftSecurityGroupIDs(cluster.VpcSecurityGroups), ",")
	attributes["snapshot_retention_days"] = int32AttrString(cluster.AutomatedSnapshotRetentionPeriod)
	attributes["state"] = awssdk.ToString(cluster.ClusterStatus)
	attributes["subnet_group_name"] = awssdk.ToString(cluster.ClusterSubnetGroupName)
	attributes["vpc_id"] = awssdk.ToString(cluster.VpcId)
	if cluster.Endpoint != nil {
		attributes["endpoint"] = awssdk.ToString(cluster.Endpoint.Address)
		attributes["port"] = int32AttrString(cluster.Endpoint.Port)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-redshift-cluster-"+firstNonEmpty(arn, name), "aws.redshift_cluster", "aws/redshift_cluster/v1", payload, attributes, firstTime(cluster.ClusterCreateTime))
}

func docDBClusterEvent(settings settings, record awsDocDBCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	arn := awssdk.ToString(cluster.DBClusterArn)
	name := awssdk.ToString(cluster.DBClusterIdentifier)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyDocDBCluster, firstNonEmpty(arn, name), name, "docdb_cluster", record.Tags)
	addSharedDBClusterAttributes(attributes, "docdb", arn, name, awssdk.ToString(cluster.Engine), awssdk.ToString(cluster.EngineVersion), awssdk.ToString(cluster.Status), awssdk.ToString(cluster.Endpoint), awssdk.ToString(cluster.ReaderEndpoint), cluster.Port, cluster.BackupRetentionPeriod, cluster.ClusterCreateTime, awssdk.ToBool(cluster.StorageEncrypted), awssdk.ToString(cluster.KmsKeyId), awssdk.ToBool(cluster.DeletionProtection), cluster.EnabledCloudwatchLogsExports, cluster.AvailabilityZones, docDBSecurityGroupIDs(cluster.VpcSecurityGroups), awssdk.ToString(cluster.DBSubnetGroup))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-docdb-cluster-"+firstNonEmpty(arn, name), "aws.docdb_cluster", "aws/docdb_cluster/v1", payload, attributes, firstTime(cluster.ClusterCreateTime))
}

func docDBInstanceEvent(settings settings, record awsDocDBInstance) (*primitives.Event, error) {
	instance := record.Instance
	arn := awssdk.ToString(instance.DBInstanceArn)
	name := awssdk.ToString(instance.DBInstanceIdentifier)
	clusterName := awssdk.ToString(instance.DBClusterIdentifier)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyDocDBInstance, firstNonEmpty(arn, name), name, "docdb_instance", record.Tags)
	addSharedDBInstanceAttributes(attributes, settings, "docdb", arn, name, clusterName, awssdk.ToString(instance.Engine), awssdk.ToString(instance.EngineVersion), awssdk.ToString(instance.DBInstanceStatus), instance.InstanceCreateTime, docDBInstanceEndpointAddress(instance), docDBInstanceEndpointPort(instance), awssdk.ToString(instance.DBInstanceClass), awssdk.ToString(instance.AvailabilityZone), docDBSubnetGroupName(instance.DBSubnetGroup), docDBInstanceVPCID(instance.DBSubnetGroup), docDBSecurityGroupIDs(instance.VpcSecurityGroups), awssdk.ToBool(instance.PubliclyAccessible))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "instance": instance, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-docdb-instance-"+firstNonEmpty(arn, name), "aws.docdb_instance", "aws/docdb_instance/v1", payload, attributes, firstTime(instance.InstanceCreateTime))
}

func neptuneClusterEvent(settings settings, record awsNeptuneCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	arn := awssdk.ToString(cluster.DBClusterArn)
	name := awssdk.ToString(cluster.DBClusterIdentifier)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyNeptuneCluster, firstNonEmpty(arn, name), name, "neptune_cluster", record.Tags)
	addSharedDBClusterAttributes(attributes, "neptune", arn, name, awssdk.ToString(cluster.Engine), awssdk.ToString(cluster.EngineVersion), awssdk.ToString(cluster.Status), awssdk.ToString(cluster.Endpoint), awssdk.ToString(cluster.ReaderEndpoint), cluster.Port, cluster.BackupRetentionPeriod, cluster.ClusterCreateTime, awssdk.ToBool(cluster.StorageEncrypted), awssdk.ToString(cluster.KmsKeyId), awssdk.ToBool(cluster.DeletionProtection), cluster.EnabledCloudwatchLogsExports, cluster.AvailabilityZones, neptuneSecurityGroupIDs(cluster.VpcSecurityGroups), awssdk.ToString(cluster.DBSubnetGroup))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-neptune-cluster-"+firstNonEmpty(arn, name), "aws.neptune_cluster", "aws/neptune_cluster/v1", payload, attributes, firstTime(cluster.ClusterCreateTime))
}

func neptuneInstanceEvent(settings settings, record awsNeptuneInstance) (*primitives.Event, error) {
	instance := record.Instance
	arn := awssdk.ToString(instance.DBInstanceArn)
	name := awssdk.ToString(instance.DBInstanceIdentifier)
	clusterName := awssdk.ToString(instance.DBClusterIdentifier)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyNeptuneInstance, firstNonEmpty(arn, name), name, "neptune_instance", record.Tags)
	addSharedDBInstanceAttributes(attributes, settings, "neptune", arn, name, clusterName, awssdk.ToString(instance.Engine), awssdk.ToString(instance.EngineVersion), awssdk.ToString(instance.DBInstanceStatus), instance.InstanceCreateTime, neptuneInstanceEndpointAddress(instance), neptuneInstanceEndpointPort(instance), awssdk.ToString(instance.DBInstanceClass), awssdk.ToString(instance.AvailabilityZone), neptuneSubnetGroupName(instance.DBSubnetGroup), neptuneInstanceVPCID(instance.DBSubnetGroup), neptuneSecurityGroupIDs(instance.VpcSecurityGroups), awssdk.ToBool(instance.PubliclyAccessible))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "instance": instance, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-neptune-instance-"+firstNonEmpty(arn, name), "aws.neptune_instance", "aws/neptune_instance/v1", payload, attributes, firstTime(instance.InstanceCreateTime))
}

func addSharedDBClusterAttributes(attributes map[string]string, engineFamily string, arn string, name string, engine string, engineVersion string, state string, endpoint string, readerEndpoint string, port *int32, backupRetentionDays *int32, createdAt *time.Time, encrypted bool, kmsKeyID string, deletionProtection bool, logExports []string, availabilityZones []string, securityGroupIDs []string, subnetGroupName string) {
	attributes["arn"] = arn
	attributes["availability_zones"] = strings.Join(cleanStrings(availabilityZones), ",")
	attributes["backups"] = boolString(awssdk.ToInt32(backupRetentionDays) > 0)
	attributes["backup_retention_days"] = int32AttrString(backupRetentionDays)
	attributes["cluster_arn"] = arn
	attributes["cluster_name"] = name
	attributes["cloudwatch_log_exports"] = strings.Join(cleanStrings(logExports), ",")
	attributes["db_cluster_identifier"] = name
	attributes["deletion_protection"] = boolString(deletionProtection)
	attributes["encryption"] = boolString(encrypted)
	attributes["engine"] = firstNonEmpty(engine, engineFamily)
	attributes["engine_version"] = engineVersion
	attributes["endpoint"] = endpoint
	attributes["internet_exposed"] = boolString(false)
	attributes["kms_key_id"] = kmsKeyID
	attributes["port"] = int32AttrString(port)
	attributes["public"] = boolString(false)
	attributes["reader_endpoint"] = readerEndpoint
	attributes["security_group_ids"] = strings.Join(securityGroupIDs, ",")
	attributes["state"] = state
	attributes["subnet_group_name"] = subnetGroupName
	addTimeAttribute(attributes, "created_at", createdAt)
}

func addSharedDBInstanceAttributes(attributes map[string]string, settings settings, engineFamily string, arn string, name string, clusterName string, engine string, engineVersion string, state string, createdAt *time.Time, endpoint string, port *int32, instanceClass string, availabilityZone string, subnetGroupName string, vpcID string, securityGroupIDs []string, publiclyAccessible bool) {
	clusterARN := awsRDSStyleClusterARN(settings, clusterName)
	attributes["arn"] = arn
	attributes["availability_zone"] = availabilityZone
	attributes["cluster_arn"] = clusterARN
	attributes["cluster_name"] = clusterName
	attributes["db_cluster_identifier"] = clusterName
	attributes["db_instance_identifier"] = name
	attributes["endpoint"] = endpoint
	attributes["engine"] = firstNonEmpty(engine, engineFamily)
	attributes["engine_version"] = engineVersion
	attributes["instance_class"] = instanceClass
	attributes["internet_exposed"] = boolString(publiclyAccessible)
	attributes["port"] = int32AttrString(port)
	attributes["public"] = boolString(publiclyAccessible)
	attributes["security_group_ids"] = strings.Join(securityGroupIDs, ",")
	attributes["state"] = state
	attributes["subnet_group_name"] = subnetGroupName
	attributes["vpc_id"] = vpcID
	addTimeAttribute(attributes, "created_at", createdAt)
}

func redshiftClusterARN(settings settings, identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:redshift:%s:%s:cluster:%s", settings.region, settings.accountID, identifier)
}

func awsRDSStyleClusterARN(settings settings, identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:rds:%s:%s:cluster:%s", settings.region, settings.accountID, identifier)
}

func redshiftTagMap(tags []redshifttypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func docDBTagMap(tags []docdbtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func neptuneTagMap(tags []neptunetypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func redshiftRoleARNs(roles []redshifttypes.ClusterIamRole) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		out = append(out, awssdk.ToString(role.IamRoleArn))
	}
	return cleanStrings(out)
}

func redshiftSecurityGroupIDs(groups []redshifttypes.VpcSecurityGroupMembership) []string {
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		out = append(out, awssdk.ToString(group.VpcSecurityGroupId))
	}
	return cleanStrings(out)
}

func docDBSecurityGroupIDs(groups []docdbtypes.VpcSecurityGroupMembership) []string {
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		out = append(out, awssdk.ToString(group.VpcSecurityGroupId))
	}
	return cleanStrings(out)
}

func neptuneSecurityGroupIDs(groups []neptunetypes.VpcSecurityGroupMembership) []string {
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		out = append(out, awssdk.ToString(group.VpcSecurityGroupId))
	}
	return cleanStrings(out)
}

func docDBInstanceEndpointAddress(instance docdbtypes.DBInstance) string {
	if instance.Endpoint == nil {
		return ""
	}
	return awssdk.ToString(instance.Endpoint.Address)
}

func docDBInstanceEndpointPort(instance docdbtypes.DBInstance) *int32 {
	if instance.Endpoint == nil {
		return nil
	}
	return instance.Endpoint.Port
}

func neptuneInstanceEndpointAddress(instance neptunetypes.DBInstance) string {
	if instance.Endpoint == nil {
		return ""
	}
	return awssdk.ToString(instance.Endpoint.Address)
}

func neptuneInstanceEndpointPort(instance neptunetypes.DBInstance) *int32 {
	if instance.Endpoint == nil {
		return nil
	}
	return instance.Endpoint.Port
}

func docDBSubnetGroupName(group *docdbtypes.DBSubnetGroup) string {
	if group == nil {
		return ""
	}
	return awssdk.ToString(group.DBSubnetGroupName)
}

func docDBInstanceVPCID(group *docdbtypes.DBSubnetGroup) string {
	if group == nil {
		return ""
	}
	return awssdk.ToString(group.VpcId)
}

func neptuneSubnetGroupName(group *neptunetypes.DBSubnetGroup) string {
	if group == nil {
		return ""
	}
	return awssdk.ToString(group.DBSubnetGroupName)
}

func neptuneInstanceVPCID(group *neptunetypes.DBSubnetGroup) string {
	if group == nil {
		return ""
	}
	return awssdk.ToString(group.VpcId)
}
