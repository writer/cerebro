module github.com/writer/cerebro

go 1.26.0

toolchain go1.26.3

replace github.com/WriterInternal/event-registry/clients/go => ./internal/eventregistry

require (
	connectrpc.com/connect v1.20.0
	github.com/WriterInternal/event-registry/clients/go v0.0.0-20260523045044-47084e3345ce
	github.com/aws/aws-sdk-go-v2 v1.41.11
	github.com/aws/aws-sdk-go-v2/config v1.32.22
	github.com/aws/aws-sdk-go-v2/credentials v1.19.21
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.40.4
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.35.4
	github.com/aws/aws-sdk-go-v2/service/bedrockruntime v1.53.3
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.64.4
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.56.2
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.305.1
	github.com/aws/aws-sdk-go-v2/service/ecr v1.58.2
	github.com/aws/aws-sdk-go-v2/service/ecs v1.82.2
	github.com/aws/aws-sdk-go-v2/service/eks v1.84.4
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.55.2
	github.com/aws/aws-sdk-go-v2/service/iam v1.54.2
	github.com/aws/aws-sdk-go-v2/service/kms v1.53.2
	github.com/aws/aws-sdk-go-v2/service/lambda v1.92.1
	github.com/aws/aws-sdk-go-v2/service/rds v1.119.0
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.33.1
	github.com/aws/aws-sdk-go-v2/service/route53 v1.63.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.103.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.42.1
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.21
	github.com/aws/aws-sdk-go-v2/service/sqs v1.43.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.1
	github.com/aws/smithy-go v1.27.0
	github.com/google/go-github/v66 v66.0.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/nats-io/nats.go v1.52.0
	github.com/neo4j/neo4j-go-driver/v5 v5.28.4
	github.com/package-url/packageurl-go v0.1.6
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.45.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.4 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)
