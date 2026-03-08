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
			RequestsPerWindow: s.app.Config.RateLimitRequests,
			Window:            s.app.Config.RateLimitWindow,
			Enabled:           true,
			TrustedProxyCIDRs: s.app.Config.RateLimitTrustedProxies,
		}
		s.rateLimiter = NewRateLimiter(rlCfg)
		s.router.Use(RateLimitMiddlewareWithLimiter(rlCfg, s.rateLimiter))
	}

	// RealIP applied after rate limiting so downstream handlers still see
	// the client IP derived from forwarded headers when available.
	s.router.Use(middleware.RealIP)

	if s.app.Config.APIAuthEnabled {
		s.router.Use(APIKeyAuth(AuthConfig{
			Enabled:        true,
			APIKeys:        s.app.Config.APIKeys,
			APIKeyProvider: s.app.APIKeysSnapshot,
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
	s.router.Get("/metrics", s.metrics)
	s.router.Get("/openapi.yaml", s.openAPISpec)
	s.router.Get("/docs", s.swaggerUI)

	s.router.Route("/api/v1", func(r chi.Router) {
		// Query endpoints
		r.Get("/tables", s.listTables)
		r.Post("/query", s.executeQuery)

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
			r.Post("/backfill-relationships", s.backfillRelationshipIDs)
			r.Post("/azure", s.syncAzure)
			r.Post("/k8s", s.syncK8s)
		})

		// Telemetry ingestion (for agents)
		r.Route("/telemetry", func(r chi.Router) {
			r.Post("/ingest", s.ingestTelemetry)
		})

		// Security Graph endpoints
		r.Route("/graph", func(r chi.Router) {
			r.Get("/diff", s.graphDiff)
			r.Get("/stats", s.graphStats)
			r.Get("/blast-radius/{principalId}", s.blastRadius)
			r.Get("/cascading-blast-radius/{principalId}", s.cascadingBlastRadius)
			r.Get("/reverse-access/{resourceId}", s.reverseAccess)
			r.Post("/rebuild", s.rebuildGraph)
			r.Post("/simulate", s.simulateGraph)
			r.Post("/evaluate-change", s.evaluateGraphChange)

			// Risk Intelligence endpoints
			r.Get("/risk-report", s.riskReport)
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
	})
}
