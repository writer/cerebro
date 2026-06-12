package sourceprojection

import (
	"net/url"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func normalizeGitHubRepository(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, "url:")
	value = strings.TrimPrefix(value, "github:")
	if strings.HasPrefix(value, "git@github.com:") {
		value = strings.TrimPrefix(value, "git@github.com:")
		value = strings.TrimSuffix(value, ".git")
		parts := strings.Split(value, "/")
		if len(parts) >= 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1])
		}
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && strings.EqualFold(parsed.Hostname(), "github.com") {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) >= 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != "" {
			repo := strings.TrimSuffix(strings.TrimSpace(parts[1]), ".git")
			return strings.TrimSpace(parts[0]) + "/" + repo
		}
		return ""
	}
	value = strings.TrimSuffix(value, ".git")
	parts := strings.Split(value, "/")
	if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != "" {
		return strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1])
	}
	return ""
}

func addContainerSourceRepositoryLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, imageURN string, containerRepositoryURN string, attrs map[string]string) string {
	sourceRepository := firstAttribute(
		attrs,
		"github_code_repositorysitory",
		"github_code_repository",
		"source_repository",
		"source_repo",
		"source_repository_url",
		"repository_url",
		"vcs_url",
		"image_source",
		"org.opencontainers.image.source",
	)
	repository := normalizeGitHubRepository(sourceRepository)
	if repository == "" {
		return ""
	}
	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repoURN == "" {
		return ""
	}
	owner, _, _ := strings.Cut(repository, "/")
	addEntity(entities, &ports.ProjectedEntity{
		URN:        repoURN,
		TenantID:   tenantID,
		SourceID:   "github",
		EntityType: "github.code.repository",
		Label:      repository,
		Attributes: compactAttributes(map[string]string{"owner_login": owner, "repository": repository}),
	})
	if orgURN := projectionURN(tenantID, "github_org", owner); owner != "" && orgURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   "github",
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner, "owner_login": owner},
		})
		addLink(links, projectedLink(tenantID, sourceID, repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "source_repository_owner", "owner_login": owner}))
	}
	attrsOut := map[string]string{"event_id": event.GetId(), "match_type": "container_source_repository", "repository": repository}
	addProjectedAttribute(attrsOut, "source_repository", sourceRepository)
	if strings.TrimSpace(imageURN) != "" {
		addLink(links, projectedLink(tenantID, sourceID, repoURN, imageURN, relationContains, attrsOut))
		addLink(links, projectedLink(tenantID, sourceID, imageURN, repoURN, relationAssociatedWith, attrsOut))
	}
	if strings.TrimSpace(containerRepositoryURN) != "" {
		addLink(links, projectedLink(tenantID, sourceID, repoURN, containerRepositoryURN, relationContains, attrsOut))
		addLink(links, projectedLink(tenantID, sourceID, containerRepositoryURN, repoURN, relationAssociatedWith, attrsOut))
	}
	return repoURN
}
