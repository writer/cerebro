module github.com/writer/cerebro

go 1.26.0

toolchain go1.26.4

replace github.com/WriterInternal/event-registry/clients/go => ./internal/eventregistry

require (
	connectrpc.com/connect v1.20.0
	github.com/WriterInternal/event-registry/clients/go v0.0.0-20260523045044-47084e3345ce
	github.com/aws/aws-sdk-go-v2 v1.41.12
	github.com/aws/aws-sdk-go-v2/config v1.32.23
	github.com/aws/aws-sdk-go-v2/credentials v1.19.22
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.49.4
	github.com/aws/aws-sdk-go-v2/service/acm v1.39.5
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.40.5
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.35.5
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.40.5
	github.com/aws/aws-sdk-go-v2/service/appsync v1.53.4
	github.com/aws/aws-sdk-go-v2/service/athena v1.58.3
	github.com/aws/aws-sdk-go-v2/service/backup v1.57.5
	github.com/aws/aws-sdk-go-v2/service/batch v1.65.5
	github.com/aws/aws-sdk-go-v2/service/bedrockruntime v1.53.4
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.65.1
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.56.3
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.58.2
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.75.1
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.69.3
	github.com/aws/aws-sdk-go-v2/service/configservice v1.64.0
	github.com/aws/aws-sdk-go-v2/service/datasync v1.59.5
	github.com/aws/aws-sdk-go-v2/service/docdb v1.49.3
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.57.9
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.32.21
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.305.2
	github.com/aws/aws-sdk-go-v2/service/ecr v1.58.2
	github.com/aws/aws-sdk-go-v2/service/ecrpublic v1.38.11
	github.com/aws/aws-sdk-go-v2/service/ecs v1.82.3
	github.com/aws/aws-sdk-go-v2/service/efs v1.42.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.84.5
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.54.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.55.3
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.46.5
	github.com/aws/aws-sdk-go-v2/service/firehose v1.43.1
	github.com/aws/aws-sdk-go-v2/service/fsx v1.66.5
	github.com/aws/aws-sdk-go-v2/service/globalaccelerator v1.36.5
	github.com/aws/aws-sdk-go-v2/service/glue v1.143.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.79.2
	github.com/aws/aws-sdk-go-v2/service/iam v1.54.3
	github.com/aws/aws-sdk-go-v2/service/identitystore v1.37.5
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.49.1
	github.com/aws/aws-sdk-go-v2/service/kafka v1.52.5
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.44.1
	github.com/aws/aws-sdk-go-v2/service/kms v1.53.2
	github.com/aws/aws-sdk-go-v2/service/lakeformation v1.48.2
	github.com/aws/aws-sdk-go-v2/service/lambda v1.92.2
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.52.1
	github.com/aws/aws-sdk-go-v2/service/neptune v1.45.2
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.61.6
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.70.6
	github.com/aws/aws-sdk-go-v2/service/opensearchserverless v1.32.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.51.9
	github.com/aws/aws-sdk-go-v2/service/pipes v1.24.5
	github.com/aws/aws-sdk-go-v2/service/rds v1.119.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.63.2
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.33.2
	github.com/aws/aws-sdk-go-v2/service/route53 v1.63.2
	github.com/aws/aws-sdk-go-v2/service/route53resolver v1.45.3
	github.com/aws/aws-sdk-go-v2/service/s3 v1.103.2
	github.com/aws/aws-sdk-go-v2/service/s3control v1.71.4
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.250.2
	github.com/aws/aws-sdk-go-v2/service/scheduler v1.18.5
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.42.1
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.71.5
	github.com/aws/aws-sdk-go-v2/service/sfn v1.42.2
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.21
	github.com/aws/aws-sdk-go-v2/service/sqs v1.43.1
	github.com/aws/aws-sdk-go-v2/service/ssm v1.69.2
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.39.5
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.2
	github.com/aws/aws-sdk-go-v2/service/vpclattice v1.22.1
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.72.3
	github.com/aws/smithy-go v1.27.1
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/getkin/kin-openapi v0.140.0
	github.com/google/go-github/v66 v66.0.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/nats-io/nats.go v1.52.0
	github.com/neo4j/neo4j-go-driver/v5 v5.28.4
	github.com/package-url/packageurl-go v0.1.6
	github.com/redis/go-redis/v9 v9.17.0
	go.opentelemetry.io/otel v1.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.44.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.44.0
	go.opentelemetry.io/otel/metric v1.44.0
	go.opentelemetry.io/otel/sdk v1.44.0
	go.opentelemetry.io/otel/sdk/metric v1.44.0
	go.opentelemetry.io/otel/trace v1.44.0
	golang.org/x/net v0.55.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.45.0
	golang.org/x/time v0.14.0
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.36.1
	k8s.io/apimachinery v0.36.1
	k8s.io/client-go v0.36.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.13 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.12.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.5 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v0.22.5 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-openapi/swag/jsonname v0.25.5 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/oasdiff/yaml v0.1.0 // indirect
	github.com/oasdiff/yaml3 v0.0.13 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.44.0 // indirect
	go.opentelemetry.io/proto/otlp v1.10.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/term v0.43.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.81.1 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260317180543-43fb72c5454a // indirect
	k8s.io/utils v0.0.0-20260210185600-b8788abfbbc2 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.2 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
