package requirements

import (
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func TestExtractStaticGoParseErrorIsScopeImpacting(t *testing.T) {
	findings := ExtractStatic([]ci.SourceFile{{Path: "broken.go", Content: []byte("package app\nfunc broken( {\n")}})
	var found bool
	for _, g := range findings.Gaps {
		if g.Code == GapGoParseError {
			found = true
		}
	}
	if !found {
		t.Fatalf("want go_parse_error gap for unparseable source, got %+v", findings.Gaps)
	}
	if len(findings.CoveredFiles) != 0 {
		t.Fatalf("unparseable file must not be covered")
	}
}

func TestExtractStaticPythonUnsupportedConstruct(t *testing.T) {
	src := `import boto3

s3 = boto3.resource("s3")
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "main.py", Content: []byte(src)}})
	var found bool
	for _, g := range findings.Gaps {
		if g.Code == GapUnsupportedPattern && g.Scope == "main.py" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want unsupported_pattern gap for boto3.resource(...), got %+v", findings.Gaps)
	}
}

func TestExtractStaticJSComputedCallUnsupported(t *testing.T) {
	src := `import { S3Client } from "@aws-sdk/client-s3";
const client = new S3Client({});
const method = "getObject";
client[method]({});
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "index.js", Content: []byte(src)}})
	var found bool
	for _, g := range findings.Gaps {
		if g.Code == GapUnsupportedPattern {
			found = true
		}
	}
	if !found {
		t.Fatalf("want unsupported_pattern gap for computed member call, got %+v", findings.Gaps)
	}
}

func TestExtractStaticUnreviewedPathForDependencyFile(t *testing.T) {
	findings := ExtractStatic([]ci.SourceFile{{Path: "go.sum", Content: []byte("module example.com/app\n")}})
	if len(findings.Gaps) != 1 || findings.Gaps[0].Code != GapUnreviewedPath {
		t.Fatalf("want exactly one unreviewed_path gap, got %+v", findings.Gaps)
	}
}

func TestExtractStaticInertAssetProducesNoGap(t *testing.T) {
	findings := ExtractStatic([]ci.SourceFile{{Path: "README.md", Content: []byte("# hello")}})
	if len(findings.Gaps) != 0 {
		t.Fatalf("want no gap for an inert doc file, got %+v", findings.Gaps)
	}
	if len(findings.CoveredFiles) != 0 {
		t.Fatalf("inert files are never 'covered' (nothing was reviewed), got %+v", findings.CoveredFiles)
	}
}

func TestExtractStaticGoBuiltinShadowedByMethodValueBlocksCompleteness(t *testing.T) {
	// (1) `len := client.GetObject; len(ctx, input)` — the builtin name
	// "len" is shadowed by a method value, so calling through it must
	// never be silently treated as the builtin and dropped.
	src := `package app

import (
	"context"

	s3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

func run(ctx context.Context, cfg any, input any) {
	client := s3.NewFromConfig(cfg)
	len := client.GetObject
	len(ctx, input)
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "shadow_builtin.go", Content: []byte(src)}})
	var found bool
	for _, g := range findings.Gaps {
		if g.Code == GapUnsupportedDynamicCall && g.Scope == "shadow_builtin.go" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want unsupported_dynamic_call gap when a builtin name is shadowed by a method value, got %+v", findings.Gaps)
	}
	for _, p := range findings.CoveredFiles {
		if p == "shadow_builtin.go" {
			t.Fatalf("file with an unresolved shadowed-builtin call must not be marked covered")
		}
	}
}

func TestExtractStaticGoPublishInsideLoggingAccessorArgument(t *testing.T) {
	// (2) A Pub/Sub Publish call embedded as the ARGUMENT to a Logging
	// fluent-accessor call (never the chain's own terminal call) must
	// still be walked and recorded, not silently skipped just because it
	// sits inside an intermediate chain link's arguments.
	src := `package app

import (
	"context"

	logging "cloud.google.com/go/logging"
	pubsub "cloud.google.com/go/pubsub"
)

func run(ctx context.Context) {
	loggingClient := logging.NewClient(ctx, "proj")
	pubsubClient := pubsub.NewClient(ctx, "proj")
	loggingClient.Logger(pubsubClient.Topic("t").Publish(ctx, nil)).Log(nil)
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "logging_arg.go", Content: []byte(src)}})
	var sawPublish, sawLog bool
	for _, op := range findings.Operations {
		if op.Service == "pubsub" && op.Token == "Topic.Publish" {
			sawPublish = true
		}
		if op.Service == "logging" && op.Token == "Logger.Log" {
			sawLog = true
		}
	}
	if !sawPublish {
		t.Fatalf("want pubsub Topic.Publish embedded in a Logger(...) argument to be recorded, got %+v", findings.Operations)
	}
	if !sawLog {
		t.Fatalf("want the outer logging Logger.Log chain call to still be recorded, got %+v", findings.Operations)
	}
}

func TestExtractStaticGoPublishAsCompositeMapKey(t *testing.T) {
	// (3) A Publish call used as a map/composite-literal KEY (not value)
	// must still be walked and recorded.
	src := `package app

import (
	"context"

	pubsub "cloud.google.com/go/pubsub"
)

func run(ctx context.Context) map[any]bool {
	client := pubsub.NewClient(ctx, "proj")
	return map[any]bool{client.Topic("t").Publish(ctx, nil): true}
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "map_key.go", Content: []byte(src)}})
	var found bool
	for _, op := range findings.Operations {
		if op.Service == "pubsub" && op.Token == "Topic.Publish" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want pubsub Topic.Publish used as a map literal key to be recorded, got %+v", findings.Operations)
	}
}

func TestExtractStaticGoParamShadowsPackageClientNeverPromoted(t *testing.T) {
	// (4) A function PARAMETER shadowing a package-level tracked SDK
	// client must take precedence over the outer client for the whole
	// function body: calling a method on the param must never be promoted
	// as if it were the package-level client.
	src := `package app

import (
	"context"

	s3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

var client = s3.NewFromConfig(nil)

func run(ctx context.Context, client any, input any) {
	client.GetObject(ctx, input)
}

func control(ctx context.Context, input any) {
	client.GetObject(ctx, input)
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "param_shadow.go", Content: []byte(src)}})
	count := 0
	for _, op := range findings.Operations {
		if op.Service == "s3" && op.Token == "GetObject" {
			count++
		}
	}
	// Control: the unshadowed package-level client in control() must
	// still be promoted exactly once.
	if count != 1 {
		t.Fatalf("want exactly one GetObject promoted from the unshadowed control() call, got %d: %+v", count, findings.Operations)
	}
	var shadowGap bool
	for _, g := range findings.Gaps {
		if g.Code == GapUnsupportedDynamicCall && g.Scope == "param_shadow.go" {
			shadowGap = true
		}
	}
	if !shadowGap {
		t.Fatalf("want an unsupported_dynamic_call gap for the call through the shadowing parameter, got %+v", findings.Gaps)
	}
}

func TestExtractStaticGoUnderscorePrefixedFileExcludedNoGap(t *testing.T) {
	// (5) Go never compiles a file whose base name starts with "_" (or
	// "."), regardless of content: it must be excluded with no promoted
	// requirement and no gap at all.
	src := `package app

import (
	"context"

	s3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

func run(ctx context.Context, client *s3.Client, input any) {
	client.GetObject(ctx, input)
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "_disabled.go", Content: []byte(src)}})
	if len(findings.Operations) != 0 {
		t.Fatalf("want no operations promoted from a file Go never compiles, got %+v", findings.Operations)
	}
	if len(findings.Gaps) != 0 {
		t.Fatalf("want no gap for an underscore-prefixed file (Go never compiles it), got %+v", findings.Gaps)
	}
	if len(findings.CoveredFiles) != 0 {
		t.Fatalf("want an underscore-prefixed file never marked covered either, got %+v", findings.CoveredFiles)
	}
}

func TestExtractStaticGoTestFileSDKImportNoGap(t *testing.T) {
	// (6) An SDK import in a `_test.go` file must never produce a
	// scope-blocking gap: Go never compiles it into the deployed binary.
	src := `package app

import (
	"testing"

	s3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestSomething(t *testing.T) {
	_ = s3.NewFromConfig(nil)
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "widget_test.go", Content: []byte(src)}})
	if len(findings.Gaps) != 0 {
		t.Fatalf("want no gap for an SDK import confined to a _test.go file, got %+v", findings.Gaps)
	}
}

func TestExtractStaticGoIndexedAssignTargetCallWalked(t *testing.T) {
	// (7) An indexed assignment TARGET expression (`m[client.Publish(...)]
	// = v`) must still be walked for an embedded call.
	src := `package app

import (
	"context"

	pubsub "cloud.google.com/go/pubsub"
)

func run(ctx context.Context, m map[any]bool) {
	client := pubsub.NewClient(ctx, "proj")
	m[client.Topic("t").Publish(ctx, nil)] = true
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "indexed_target.go", Content: []byte(src)}})
	var found bool
	for _, op := range findings.Operations {
		if op.Service == "pubsub" && op.Token == "Topic.Publish" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want pubsub Topic.Publish embedded in an indexed assignment target to be recorded, got %+v", findings.Operations)
	}
}

func TestExtractStaticGoLocalAWSShadowNeverNarrowsResource(t *testing.T) {
	// (8) A local variable/parameter named "aws" that shadows the
	// canonical `github.com/aws/aws-sdk-go-v2/aws` import must never be
	// trusted to narrow a resource via its own ".String(...)" method, even
	// though it has the same import alias name globally in the file.
	src := `package app

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	s3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

type fakeAWS struct{ v string }

func (f fakeAWS) String() *string { return &f.v }

func run(ctx context.Context, aws fakeAWS) {
	client := s3.NewFromConfig(nil)
	client.GetObject(ctx, struct {
		Bucket *string
	}{Bucket: aws.String()})
}

func control(ctx context.Context) {
	client := s3.NewFromConfig(nil)
	client.GetObject(ctx, struct {
		Bucket *string
	}{Bucket: awssdk.String("my-bucket")})
}
`
	findings := ExtractStatic([]ci.SourceFile{{Path: "aws_shadow.go", Content: []byte(src)}})
	var ops []StaticOperation
	for _, op := range findings.Operations {
		if op.Service == "s3" && op.Token == "GetObject" {
			ops = append(ops, op)
		}
	}
	if len(ops) != 2 {
		t.Fatalf("want exactly two GetObject operations (run's shadowed call, control's canonical call), got %+v", ops)
	}
	// ops[0] is run() (shadowed local "aws"): its resource must never be
	// narrowed by the shadow's own String() method.
	if len(ops[0].Resources) != 0 {
		t.Fatalf("want a locally-shadowed \"aws\" identifier's .String() never trusted to narrow a resource, got %+v", ops[0].Resources)
	}
	// ops[1] is control() (canonical, unshadowed aws.String(...)): its
	// resource must still be narrowed.
	if len(ops[1].Resources) == 0 || ops[1].Resources[0] != "arn:aws:s3:::my-bucket/*" {
		t.Fatalf("want canonical aws.String(...) to still narrow the control call's resource, got %+v", ops[1].Resources)
	}
}
