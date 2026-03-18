//go:generate sh -c "cd ../.. && go run ./scripts/openapi_route_parity.go --write"

package api

import (
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (s *Server) setupMiddleware() {
	s.router.Use(middleware.RequestID)
	s.router.Use(TracingMiddleware)
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(SecurityHeaders())
	s.router.Use(s.graphBuildWarningHeaders)
	s.router.Use(middleware.Timeout(60 * time.Second))
	s.router.Use(middleware.Compress(5))
	s.router.Use(MaxBodySize(DefaultMaxBodySize))
	s.router.Use(MetricsMiddleware)

	if len(s.app.Config.CORSAllowedOrigins) > 0 {
		s.router.Use(CORS(s.app.Config.CORSAllowedOrigins))
	}

	// Rate limiting must run BEFORE RealIP so that it sees the original
	// socket peer in RemoteAddr.  RealIP rewrites RemoteAddr from
	// forwarded headers, which an untrusted client could spoof.
	if s.app.Config.RateLimitEnabled {
		rlCfg := RateLimitConfig{
			RequestsPerWindow:  s.app.Config.RateLimitRequests,
			Window:             s.app.Config.RateLimitWindow,
			Enabled:            true,
			CredentialProvider: s.app.APICredentialsSnapshot,
			CredentialLookup:   s.app.LookupAPICredential,
			TrustedProxyCIDRs:  s.app.Config.RateLimitTrustedProxies,
		}
		s.rateLimiter = NewRateLimiter(rlCfg)
		s.router.Use(RateLimitMiddlewareWithLimiter(rlCfg, s.rateLimiter))
	}

	// RealIP applied after rate limiting so downstream handlers still see
	// the client IP derived from forwarded headers when available.
	s.router.Use(middleware.RealIP)

	if s.app.Config.APIAuthEnabled {
		s.router.Use(APIKeyAuth(AuthConfig{
			Enabled:              true,
			APIKeys:              s.app.Config.APIKeys,
			APIKeyProvider:       s.app.APIKeysSnapshot,
			Credentials:          s.app.Config.APICredentials,
			CredentialProvider:   s.app.APICredentialsSnapshot,
			CredentialLookup:     s.app.LookupAPICredential,
			AuthorizationServers: append([]string(nil), s.app.Config.APIAuthorizationServers...),
		}))
	}

	// Enforce RBAC permissions when auth is enabled
	if s.app.Config.APIAuthEnabled && s.app.RBAC != nil {
		s.router.Use(RBACMiddleware(s.app.RBAC))
	}
}

func (s *Server) setupRoutes() {
	s.router.Get("/health", s.health)
	s.router.Get("/ready", s.ready)
	s.router.Get("/status", s.status)
	s.router.Get("/metrics", s.metrics)
	s.router.Get("/openapi.yaml", s.openAPISpec)
	s.router.Get("/docs", s.swaggerUI)
	s.router.Get("/.well-known/oauth-protected-resource", s.agentSDKProtectedResourceMetadata)

	s.router.Route("/api/v1", func(r chi.Router) {
		// Query endpoints
		r.Get("/tables", s.listTables)
		r.Post("/query", s.executeQuery)
		r.Get("/status/freshness", s.statusFreshness)

		// Asset endpoints
		r.Route("/assets", func(r chi.Router) {
			r.Get("/{table}", s.listAssets)
			r.Get("/{table}/{id}", s.getAsset)
		})

		// Policy endpoints
		r.Route("/policies", func(r chi.Router) {
			r.Get("/", s.listPolicies)
			r.Get("/{id}", s.getPolicy)
			r.Get("/{id}/versions", s.listPolicyVersions)
			r.Post("/", s.createPolicy)
			r.Put("/{id}", s.updatePolicy)
			r.Post("/{id}/rollback", s.rollbackPolicy)
			r.Post("/{id}/dry-run", s.dryRunPolicyChange)
			r.Delete("/{id}", s.deletePolicy)
			r.Post("/evaluate", s.evaluatePolicy)
		})
		r.Route("/policy", func(r chi.Router) {
			r.Post("/evaluate", s.evaluatePolicy)
		})

		// Finding endpoints
		r.Route("/findings", func(r chi.Router) {
			r.Get("/", s.listFindings)
			r.Get("/stats", s.findingsStats)
			r.Get("/export", s.exportFindings)
			r.Get("/{id}", s.getFinding)
			r.Delete("/{id}", s.deleteFinding)
			r.Post("/scan", s.scanFindings)
			r.Post("/{id}/resolve", s.resolveFinding)
			r.Post("/{id}/suppress", s.suppressFinding)
			r.Put("/{id}/assign", s.assignFinding)
			r.Put("/{id}/due", s.setFindingDueDate)
			r.Post("/{id}/notes", s.addFindingNote)
			r.Post("/{id}/tickets", s.linkFindingTicket)
		})
		r.Get("/signals/dashboard", s.signalsDashboard)

		// Business entity analytics endpoints
		r.Route("/entities", func(r chi.Router) {
			r.Get("/{id}/cohort", s.getEntityCohort)
			r.Get("/{id}/outlier-score", s.getEntityOutlierScore)
		})

		// Reporting endpoints
		r.Route("/reports", func(r chi.Router) {
			r.Get("/executive-summary", s.executiveSummary)
			r.Get("/risk-summary", s.riskSummary)
			r.Get("/compliance/{framework}", s.frameworkComplianceReport)
		})

		// Compliance endpoints
		r.Route("/compliance", func(r chi.Router) {
			r.Get("/frameworks", s.listFrameworks)
			r.Get("/frameworks/{id}", s.getFramework)
			r.Get("/frameworks/{id}/report", s.generateComplianceReport)
			r.Get("/frameworks/{id}/pre-audit", s.preAuditCheck)
			r.Get("/frameworks/{id}/export", s.exportAuditPackage)
		})

		// Agent endpoints
		r.Route("/agents", func(r chi.Router) {
			r.Get("/", s.listAgents)
			r.Get("/{id}", s.getAgent)
			r.Post("/sessions", s.createSession)
			r.Get("/sessions/{id}", s.getSession)
			r.Post("/sessions/{id}/approve", s.approveSessionToolCall)
			r.Post("/sessions/{id}/messages", s.sendMessage)
			r.Get("/sessions/{id}/messages", s.getMessages)
		})

		// Incident response endpoints
		r.Route("/incidents", func(r chi.Router) {
			r.Post("/", s.createIncident)
			r.Get("/playbooks", s.listPlaybooks)
			r.Get("/playbooks/{id}", s.getPlaybook)
		})

		// Ticketing endpoints
		r.Route("/tickets", func(r chi.Router) {
			r.Get("/", s.listTickets)
			r.Post("/", s.createTicket)
			r.Get("/{id}", s.getTicket)
			r.Put("/{id}", s.updateTicket)
			r.Post("/{id}/comments", s.addComment)
			r.Post("/{id}/close", s.closeTicket)
		})

		// Identity/Access Review endpoints
		r.Route("/identity", func(r chi.Router) {
			r.Get("/reviews", s.listReviews)
			r.Post("/reviews", s.createReview)
			r.Get("/reviews/{id}", s.getReview)
			r.Post("/reviews/{id}/start", s.startReview)
			r.Get("/reviews/{id}/items", s.listReviewItems)
			r.Post("/reviews/{id}/items", s.addReviewItem)
			r.Post("/reviews/{id}/items/{itemId}/decide", s.recordDecision)

			// Stale access detection
			r.Get("/stale-access", s.detectStaleAccess)
			r.Get("/report", s.identityReport)
		})

		// Attack Path endpoints
		r.Route("/attack-paths", func(r chi.Router) {
			r.Get("/", s.listAttackPaths)
			r.Post("/analyze", s.analyzeAttackPaths)
			r.Get("/{id}", s.getAttackPath)
			r.Get("/graph", s.getGraph)
			r.Post("/graph/nodes", s.addNode)
			r.Post("/graph/edges", s.addEdge)
		})
		r.Post("/impact-analysis", s.impactAnalysis)

		// Provider endpoints
		r.Route("/providers", func(r chi.Router) {
			r.Get("/", s.listProviders)
			r.Get("/{name}", s.getProvider)
			r.Post("/{name}/configure", s.configureProvider)
			r.Post("/{name}/sync", s.syncProvider)
			r.Get("/{name}/schema", s.getProviderSchema)
			r.Post("/{name}/test", s.testProvider)
		})

		// Webhook endpoints
		r.Route("/webhooks", func(r chi.Router) {
			r.Get("/", s.listWebhooks)
			r.Post("/", s.createWebhook)
			r.Get("/{id}", s.getWebhook)
			r.Delete("/{id}", s.deleteWebhook)
			r.Get("/{id}/deliveries", s.getWebhookDeliveries)
			r.Post("/test", s.testWebhook)
		})

		// Audit log endpoints
		r.Route("/audit", func(r chi.Router) {
			r.Get("/", s.listAuditLogs)
		})

		// Scheduler endpoints
		r.Route("/scheduler", func(r chi.Router) {
			r.Get("/status", s.schedulerStatus)
			r.Get("/jobs", s.listJobs)
			r.Post("/jobs/{name}/run", s.runJob)
			r.Post("/jobs/{name}/enable", s.enableJob)
			r.Post("/jobs/{name}/disable", s.disableJob)
		})

		// Notification endpoints
		r.Route("/notifications", func(r chi.Router) {
			r.Get("/", s.listNotifiers)
			r.Post("/test", s.testNotifications)
			r.Get("/digest", s.dailyDigest)
		})

		// Slack integration
		r.Post("/slack/commands", s.slackCommands)

		// Remediation/automation endpoints
		r.Route("/remediation", func(r chi.Router) {
			r.Get("/rules", s.listRemediationRules)
			r.Post("/rules", s.createRemediationRule)
			r.Get("/rules/{id}", s.getRemediationRule)
			r.Put("/rules/{id}", s.updateRemediationRule)
			r.Delete("/rules/{id}", s.deleteRemediationRule)
			r.Post("/rules/{id}/enable", s.enableRemediationRule)
			r.Post("/rules/{id}/disable", s.disableRemediationRule)
			r.Get("/executions", s.listRemediationExecutions)
			r.Get("/executions/{id}", s.getRemediationExecution)
			r.Post("/executions/{id}/approve", s.approveExecution)
			r.Post("/executions/{id}/reject", s.rejectExecution)
		})

		// Admin/health endpoints
		r.Route("/admin", func(r chi.Router) {
			r.Get("/health", s.adminHealth)
			r.Get("/sync/status", s.syncStatus)
			r.Route("/agent-sdk", func(r chi.Router) {
				r.Get("/credentials", s.listAdminAgentSDKCredentials)
				r.Post("/credentials", s.createAdminAgentSDKCredential)
				r.Get("/credentials/{credential_id}", s.getAdminAgentSDKCredential)
				r.Post("/credentials/{credential_id}:rotate", s.rotateAdminAgentSDKCredential)
				r.Post("/credentials/{credential_id}:revoke", s.revokeAdminAgentSDKCredential)
			})
		})

		// Threat Intelligence endpoints
		r.Route("/threatintel", func(r chi.Router) {
			r.Get("/feeds", s.listThreatFeeds)
			r.Post("/feeds/{id}/sync", s.syncThreatFeed)
			r.Get("/stats", s.threatIntelStats)
			r.Get("/lookup/ip/{ip}", s.lookupIP)
			r.Get("/lookup/domain/{domain}", s.lookupDomain)
			r.Get("/lookup/cve/{cve}", s.lookupCVE)
		})

		// Runtime Detection endpoints
		r.Route("/runtime", func(r chi.Router) {
			r.Get("/detections", s.listDetectionRules)
			r.Post("/events", s.ingestRuntimeEvent)
			r.Get("/findings", s.listRuntimeFindings)
			r.Get("/responses", s.listResponsePolicies)
			r.Post("/responses/{id}/enable", s.enableResponsePolicy)
			r.Post("/responses/{id}/disable", s.disableResponsePolicy)
		})

		// Lineage endpoints
		r.Route("/lineage", func(r chi.Router) {
			r.Get("/{assetId}", s.getAssetLineage)
			r.Get("/by-commit/{sha}", s.getLineageByCommit)
			r.Get("/by-image/{digest}", s.getLineageByImage)
			r.Post("/drift/{assetId}", s.detectDrift)
		})

		// RBAC endpoints
		r.Route("/rbac", func(r chi.Router) {
			r.Get("/roles", s.listRoles)
			r.Get("/permissions", s.listPermissions)
			r.Post("/users", s.createUser)
			r.Get("/users/{id}", s.getUser)
			r.Post("/users/{id}/roles", s.assignRole)
			r.Get("/tenants", s.listTenants)
			r.Post("/tenants", s.createTenant)
		})

		// Scan management endpoints
		r.Route("/scan", func(r chi.Router) {
			r.Get("/watermarks", s.getScanWatermarks)
			r.Get("/coverage", s.getPolicyCoverage)
		})

		// Sync management endpoints
		r.Route("/sync", func(r chi.Router) {
			r.Post("/aws", s.syncAWS)
			r.Post("/aws-org", s.syncAWSOrg)
			r.Post("/backfill-relationships", s.backfillRelationshipIDs)
			r.Post("/azure", s.syncAzure)
			r.Post("/gcp", s.syncGCP)
			r.Post("/gcp-asset", s.syncGCPAsset)
			r.Post("/k8s", s.syncK8s)
		})

		// Telemetry ingestion (for agents)
		r.Route("/telemetry", func(r chi.Router) {
			r.Post("/ingest", s.ingestTelemetry)
		})

		// Agent SDK gateway over the shared tool registry.
		r.Route("/agent-sdk", func(r chi.Router) {
			r.Get("/tools", s.listAgentSDKTools)
			r.Post("/tools/{tool_id:[A-Za-z0-9._-]+}:call", s.agentSDKCallTool)
			r.Get("/context/{entity_id}", s.agentSDKContext)
			r.Post("/report", s.agentSDKReport)
			r.Get("/quality", s.agentSDKQuality)
			r.Get("/leverage", s.agentSDKLeverage)
			r.Get("/templates", s.agentSDKTemplates)
			r.Post("/check", s.agentSDKCheck)
			r.Post("/simulate", s.agentSDKSimulate)
			r.Post("/observations", s.agentSDKObservation)
			r.Post("/claims", s.agentSDKClaim)
			r.Post("/decisions", s.agentSDKDecision)
			r.Post("/outcomes", s.agentSDKOutcome)
			r.Post("/annotations", s.agentSDKAnnotation)
			r.Post("/identity/resolve", s.agentSDKResolveIdentity)
			r.Get("/schema/nodes", s.listAgentSDKNodeSchema)
			r.Get("/schema/edges", s.listAgentSDKEdgeSchema)
		})
		r.Get("/mcp", s.agentSDKMCPStream)
		r.Post("/mcp", s.agentSDKMCP)

		// Shared platform primitives
		r.Route("/platform", func(r chi.Router) {
			r.Get("/executions", s.listPlatformExecutions)
			r.Get("/entities", s.listPlatformEntities)
			r.Get("/entities/search", s.searchPlatformEntities)
			r.Get("/entities/suggest", s.suggestPlatformEntities)
			r.Get("/entities/facets", s.listPlatformEntityFacets)
			r.Get("/entities/facets/{facet_id}", s.getPlatformEntityFacet)
			r.Get("/entities/{entity_id}/at", s.getPlatformEntityAtTime)
			r.Get("/entities/{entity_id}/diff", s.getPlatformEntityTimeDiff)
			r.Get("/entities/{entity_id}", s.getPlatformEntity)
			r.Route("/graph", func(r chi.Router) {
				r.Get("/queries", s.platformGraphQueriesGet)
				r.Post("/queries", s.platformGraphQueries)
				r.Post("/diffs", s.createPlatformGraphDiff)
				r.Get("/diffs/{diff_id}", s.getPlatformGraphDiffArtifact)
				r.Get("/diffs/{diff_id}/details", s.getPlatformGraphDiffDetails)
				r.Get("/changelog", s.listPlatformGraphChangelog)
				r.Get("/templates", s.platformGraphTemplates)
				r.Get("/snapshots", s.listPlatformGraphSnapshots)
				r.Get("/snapshots/current", s.getCurrentPlatformGraphSnapshot)
				r.Get("/snapshots/{snapshot_id}", s.getPlatformGraphSnapshot)
				r.Get("/snapshots/{snapshot_id}/ancestry", s.getPlatformGraphSnapshotAncestry)
				r.Get("/snapshots/{snapshot_id}/diffs/{other_snapshot_id}", s.getPlatformGraphSnapshotDiff)
			})
			r.Route("/intelligence", func(r chi.Router) {
				r.Get("/measures", s.listPlatformIntelligenceMeasures)
				r.Get("/checks", s.listPlatformIntelligenceChecks)
				r.Get("/section-envelopes", s.listPlatformIntelligenceSectionEnvelopes)
				r.Get("/section-envelopes/{envelope_id}", s.getPlatformIntelligenceSectionEnvelope)
				r.Get("/section-fragments", s.listPlatformIntelligenceSectionFragments)
				r.Get("/section-fragments/{fragment_id}", s.getPlatformIntelligenceSectionFragment)
				r.Get("/benchmark-packs", s.listPlatformIntelligenceBenchmarkPacks)
				r.Get("/benchmark-packs/{pack_id}", s.getPlatformIntelligenceBenchmarkPack)
				r.Get("/reports", s.listPlatformIntelligenceReports)
				r.Get("/reports/{id}", s.getPlatformIntelligenceReport)
				r.Get("/reports/{id}/runs", s.listPlatformIntelligenceReportRuns)
				r.Post("/reports/{id}/runs", s.createPlatformIntelligenceReportRun)
				r.Post("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}:retry", s.retryPlatformIntelligenceReportRun)
				r.Post("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}:cancel", s.cancelPlatformIntelligenceReportRun)
				r.Get("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}", s.getPlatformIntelligenceReportRun)
				r.Get("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}/control", s.getPlatformIntelligenceReportRunControl)
				r.Get("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}/retry-policy", s.getPlatformIntelligenceReportRunRetryPolicy)
				r.Put("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}/retry-policy", s.updatePlatformIntelligenceReportRunRetryPolicy)
				r.Get("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}/attempts", s.listPlatformIntelligenceReportRunAttempts)
				r.Get("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}/events", s.listPlatformIntelligenceReportRunEvents)
				r.Get("/reports/{id}/runs/report_run:{run_id:[A-Za-z0-9-]+}/stream", s.streamPlatformIntelligenceReportRun)
				r.Get("/event-patterns", s.graphIntelligenceEventPatterns)
				r.Get("/event-correlations", s.graphIntelligenceEventCorrelations)
				r.Get("/event-anomalies", s.graphIntelligenceEventAnomalies)
				r.Get("/insights", s.graphIntelligenceInsights)
				r.Get("/quality", s.graphIntelligenceQuality)
				r.Get("/metadata-quality", s.graphIntelligenceMetadataQuality)
				r.Get("/claim-conflicts", s.graphIntelligenceClaimConflicts)
				r.Get("/entity-summary", s.graphIntelligenceEntitySummary)
				r.Get("/leverage", s.graphIntelligenceLeverage)
				r.Get("/calibration/weekly", s.graphIntelligenceWeeklyCalibration)
			})
			r.Route("/knowledge", func(r chi.Router) {
				r.Get("/evidence", s.listPlatformKnowledgeEvidence)
				r.Get("/evidence/{evidence_id}", s.getPlatformKnowledgeEvidence)
				r.Get("/diffs", s.listPlatformKnowledgeDiffs)
				r.Get("/observations", s.listPlatformKnowledgeObservations)
				r.Get("/observations/{observation_id}", s.getPlatformKnowledgeObservation)
				r.Post("/observations", s.platformWriteObservation)
				r.Get("/claim-groups", s.listPlatformKnowledgeClaimGroups)
				r.Post("/claim-groups/{group_id}/adjudications", s.adjudicatePlatformKnowledgeClaimGroup)
				r.Get("/claim-groups/{group_id}", s.getPlatformKnowledgeClaimGroup)
				r.Get("/claim-diffs", s.listPlatformKnowledgeClaimDiffs)
				r.Get("/claims", s.listPlatformKnowledgeClaims)
				r.Get("/claims/{claim_id}", s.getPlatformKnowledgeClaim)
				r.Get("/claims/{claim_id}/timeline", s.getPlatformKnowledgeClaimTimeline)
				r.Get("/claims/{claim_id}/explanation", s.getPlatformKnowledgeClaimExplanation)
				r.Get("/claims/{claim_id}/proofs", s.getPlatformKnowledgeClaimProofs)
				r.Post("/claims", s.platformWriteClaim)
				r.Post("/decisions", s.platformWriteDecision)
			})
			r.Route("/jobs", func(r chi.Router) {
				r.Get("/{id}", s.getPlatformJob)
			})
		})

		// Security application endpoints on the shared graph platform.
		r.Route("/security", func(r chi.Router) {
			r.Route("/analyses", func(r chi.Router) {
				r.Post("/attack-paths/jobs", s.createSecurityAttackPathJob)
			})
		})

		// Graph platform endpoints
		r.Route("/graph", func(r chi.Router) {
			r.Get("/stats", s.graphStats)
			r.Get("/ingest/health", s.graphIngestHealth)
			r.Get("/ingest/dead-letter", s.graphIngestDeadLetter)
			r.Get("/ingest/contracts", s.graphIngestContracts)
			r.Get("/schema", s.getGraphSchema)
			r.Get("/schema/health", s.getGraphSchemaHealth)
			r.Post("/actuate/recommendation", s.graphActuateRecommendation)
			r.Post("/write/annotation", s.graphAnnotateEntity)
			r.Post("/write/outcome", s.graphWriteOutcome)
			r.Post("/identity/resolve", s.graphResolveIdentity)
			r.Post("/identity/split", s.graphSplitIdentity)
			r.Post("/identity/review", s.graphReviewIdentity)
			r.Get("/identity/calibration", s.graphIdentityCalibration)
			r.Post("/schema/register", s.registerGraphSchema)
			r.Get("/blast-radius/{principalId}", s.blastRadius)
			r.Get("/cascading-blast-radius/{principalId}", s.cascadingBlastRadius)
			r.Get("/reverse-access/{resourceId}", s.reverseAccess)
			r.Post("/rebuild", s.rebuildGraph)
			r.Post("/simulate", s.simulateGraph)
			r.Post("/evaluate-change", s.evaluateGraphChange)

			// Risk Intelligence endpoints
			r.Get("/risk-report", s.riskReport)
			r.Get("/risk-feedback", s.graphRiskFeedback)
			r.Get("/outcomes", s.listGraphOutcomes)
			r.Post("/outcomes", s.recordGraphOutcome)
			r.Post("/rule-discovery/run", s.runGraphRuleDiscovery)
			r.Get("/rule-discovery/candidates", s.listGraphRuleDiscoveryCandidates)
			r.Post("/rule-discovery/candidates/{id}/decision", s.decideGraphRuleDiscoveryCandidate)
			r.Post("/cross-tenant/patterns/build", s.buildCrossTenantPatternSamples)
			r.Post("/cross-tenant/patterns/ingest", s.ingestCrossTenantPatternSamples)
			r.Get("/cross-tenant/patterns", s.listCrossTenantPatterns)
			r.Get("/cross-tenant/matches", s.matchCrossTenantPatterns)
			r.Get("/toxic-combinations", s.listToxicCombinations)
			r.Get("/attack-paths", s.listGraphAttackPaths)
			r.Get("/attack-paths/{id}/simulate-fix", s.simulateAttackPathFix)
			r.Get("/chokepoints", s.listChokepoints)
			r.Get("/privilege-escalation/{principalId}", s.detectPrivilegeEscalation)

			// Peer Groups and Access Analysis endpoints
			r.Get("/peer-groups", s.analyzePeerGroups)
			r.Get("/effective-permissions/{principalId}", s.getEffectivePermissions)
			r.Get("/compare-permissions", s.comparePermissions)

			// Graph-based Access Review endpoints
			r.Post("/access-reviews", s.createGraphAccessReview)
			r.Get("/access-reviews", s.listGraphAccessReviews)
			r.Get("/access-reviews/{id}", s.getGraphAccessReview)
			r.Post("/access-reviews/{id}/start", s.startGraphAccessReview)
			r.Post("/access-reviews/{id}/items/{itemId}/decide", s.decideGraphAccessReviewItem)

			// Visualization endpoints
			r.Get("/visualize/attack-path/{id}", s.visualizeAttackPath)
			r.Get("/visualize/toxic-combination/{id}", s.visualizeToxicCombination)
			r.Get("/visualize/blast-radius/{principalId}", s.visualizeBlastRadius)
			r.Get("/visualize/report", s.visualizeReport)
		})

		// Organizational flow endpoints
		r.Route("/org", func(r chi.Router) {
			r.Get("/expertise/queries", s.whoKnows)
			r.Post("/team-recommendations", s.recommendTeam)
			r.Post("/reorg-simulations", s.simulateReorg)
			r.Get("/information-flow", s.orgInformationFlow)
			r.Get("/clock-speed", s.orgClockSpeed)
			r.Get("/recommended-connections", s.orgRecommendedConnections)
			r.Get("/onboarding/{id}/plan", s.orgOnboardingPlan)
			r.Get("/meeting-insights", s.orgMeetingInsights)
			r.Get("/meetings/{id}/analysis", s.orgMeetingAnalysis)
		})
	})
}
