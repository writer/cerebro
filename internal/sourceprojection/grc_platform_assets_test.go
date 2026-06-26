package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectGRCVulnerableAssetLinksPlatformResources(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-platform",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":       "vanta",
			"target_id":      "vanta-asset-1",
			"target_name":    "ip-10-86-43-17.ec2.internal: i-0f359ce073424f8d6",
			"hostnames":      "ip-10-86-43-17.ec2.internal",
			"ip_addresses":   "10.86.43.17",
			"integration_id": "aws",
			"platform_asset_refs": `[` +
				`{"provider":"aws","resource_id":"arn:aws:ec2:us-east-1:381491964434:instance/i-0f359ce073424f8d6","resource_name":"ip-10-86-43-17.ec2.internal","resource_type":"SERVER","scanner_resource_id":"scanner-resource-1","hostnames":"ip-10-86-43-17.ec2.internal","ips":"10.86.43.17"}` +
				`]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:vanta-asset-1"
	awsInstanceURN := "urn:cerebro:writer:aws_ec2_instance:arn:aws:ec2:us-east-1:381491964434:instance/i-0f359ce073424f8d6"
	hostURN := "urn:cerebro:writer:internet_host:ip-10-86-43-17.ec2.internal"
	ipURN := "urn:cerebro:writer:internet_ip:10.86.43.17"
	accountURN := "urn:cerebro:writer:cloud_account:381491964434"

	if entity := state.entities[awsInstanceURN]; entity == nil || entity.EntityType != "aws.ec2.instance" || entity.SourceID != "aws" {
		t.Fatalf("AWS instance entity missing: %#v", entity)
	}
	if entity := state.entities[accountURN]; entity != nil {
		t.Fatalf("GRC projection must not upsert shared AWS account entity: %#v", entity)
	}
	assertProjectedLink(t, state, targetURN, relationRepresents, awsInstanceURN)
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, targetURN, relationRepresents, ipURN)
	assertProjectedLinkMissing(t, state, awsInstanceURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, awsInstanceURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, awsInstanceURN, relationRepresents, ipURN)

	// The platform resource gets a human-friendly label so dashboards and the
	// ask-the-graph UX surface "ip-10-86-43-17.ec2.internal" instead of the URN.
	if entity := state.entities[awsInstanceURN]; entity == nil || entity.Label == awsInstanceURN || entity.Label == "" {
		t.Fatalf("aws instance label = %q, want human-readable resource_name", entity.Label)
	}

	// Vanta-discovered platform resources must back-link to the originating
	// GRC integration so that orphan checks and source-of-truth queries can
	// traverse from github.code.repository / aws.* into the integration node.
	integrationURN := "urn:cerebro:writer:source:vanta:integration:aws"
	assertProjectedLink(t, state, awsInstanceURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerableAssetLabelsAndLinksGitHubRepoToIntegration(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-github",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "github-repo-asset",
			"integration_id":      "github",
			"platform_asset_refs": `[{"provider":"github","resource_id":"1242719606","resource_name":"Writer/cerebro","resource_type":"code_repository"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	repoURN := "urn:cerebro:writer:github_code_repository:1242719606"
	orgURN := "urn:cerebro:writer:github_org:Writer"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:github"

	repo := state.entities[repoURN]
	if repo == nil {
		t.Fatalf("github code repository entity %q missing", repoURN)
	}
	if repo.Label != "Writer/cerebro" {
		t.Fatalf("github repo label = %q, want resource_name %q", repo.Label, "Writer/cerebro")
	}
	if got := repo.Attributes["owner_login"]; got != "Writer" {
		t.Fatalf("github repo owner_login = %q, want Writer", got)
	}
	if org := state.entities[orgURN]; org == nil || org.EntityType != "github.org" {
		t.Fatalf("github org entity %q missing or wrong type: %#v", orgURN, org)
	}
	assertProjectedLink(t, state, repoURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, repoURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerableAssetDoesNotCreateGitHubAliasForNonGitHubSlashName(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-non-github-slash",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "non-github-slash-asset",
			"integration_id":      "aws",
			"platform_asset_refs": `[{"provider":"aws","resource_id":"arn:aws:s3:::prod-app","resource_name":"prod/app","resource_type":"bucket"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	if entity := state.entities["urn:cerebro:writer:github_code_repository:prod/app"]; entity != nil {
		t.Fatalf("non-github platform asset unexpectedly created github repo alias: %#v", entity)
	}
	if entity := state.entities["urn:cerebro:writer:github_org:prod"]; entity != nil {
		t.Fatalf("non-github platform asset unexpectedly created github org: %#v", entity)
	}
}

func TestGRCAWSResourceTypeFromARNHandlesAPIGatewayCustomDomain(t *testing.T) {
	got := grcAWSResourceTypeFromARN("arn:aws:apigateway:us-east-1::/domainnames/api.writer.com")
	if got != "apigateway_domain" {
		t.Fatalf("grcAWSResourceTypeFromARN() = %q, want apigateway_domain", got)
	}
}
