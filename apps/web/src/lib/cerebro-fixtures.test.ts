import { afterEach, describe, expect, it } from "vitest";

import { cerebroFixtureResponseFor, isCerebroFixtureMode, resetCerebroFixtureStateForTests } from "./cerebro-fixtures";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;
const originalApiBase = process.env.CEREBRO_API_BASE;

const withFixtureMode = () => {
  process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
  delete process.env.CEREBRO_API_BASE;
};

const parseFixture = (response: NonNullable<ReturnType<typeof cerebroFixtureResponseFor>>) =>
  JSON.parse(response.body) as Record<string, unknown>;

describe("cerebro fixture proxy responses", () => {
  afterEach(() => {
    resetCerebroFixtureStateForTests();
    if (originalFixtureMode === undefined) delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    else process.env.CEREBRO_WEB_FIXTURE_MODE = originalFixtureMode;
    if (originalApiBase === undefined) delete process.env.CEREBRO_API_BASE;
    else process.env.CEREBRO_API_BASE = originalApiBase;
  });

  it("is disabled unless the explicit fixture flag or fixture API base is set", () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    delete process.env.CEREBRO_API_BASE;
    expect(isCerebroFixtureMode()).toBe(false);
    expect(cerebroFixtureResponseFor({ method: "GET", path: "grc/dashboard" })).toBeNull();

    process.env.CEREBRO_API_BASE = "fixture://local";
    expect(isCerebroFixtureMode()).toBe(true);
  });

  it("returns a realistic GRC dashboard fixture", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({ method: "GET", path: "grc/dashboard" });
    expect(response?.status).toBe(200);
    expect(response?.headers["x-cerebro-fixture"]).toBe("true");
    const payload = parseFixture(response!);
    expect(payload.summary).toMatchObject({ open_findings: 3, critical_findings: 1 });
    expect(payload.findings).toHaveLength(3);
    expect(payload).not.toHaveProperty("product_areas");
  });

  it("rejects fixture writes without an explicit handler", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({
      method: "POST",
      path: "unknown/write",
      body: JSON.stringify({ name: "No handler" }),
    });

    expect(response?.status).toBe(404);
    expect(parseFixture(response!)).toMatchObject({
      error: "No fixture is registered for unknown/write",
    });
  });

  it("filters fixture findings by severity", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/findings",
      searchParams: new URLSearchParams("severity=high"),
    });
    const payload = parseFixture(response!);
    expect(payload.findings).toMatchObject([{ id: "demo-finding-high" }]);
  });

  it("returns and filters vendor fixtures", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({ method: "GET", path: "grc/vendors" });
    expect(response?.status).toBe(200);
    expect(parseFixture(response!)).toMatchObject({
      summary: { total_vendors: 2, risk_queue_vendors: 1 },
      vendors: [
        expect.objectContaining({ name: "Core SSO" }),
        expect.objectContaining({ name: "Payments Processor" }),
      ],
    });

    const filtered = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/vendors",
      searchParams: new URLSearchParams("queue=true"),
    });
    expect(parseFixture(filtered!)).toMatchObject({
      summary: { total_vendors: 1, risk_queue_vendors: 1 },
      vendors: [expect.objectContaining({ name: "Core SSO" })],
    });
  });

  it("creates vendor fixtures and returns them in the register", () => {
    withFixtureMode();
    const created = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/vendors",
      body: JSON.stringify({
        tenant_id: "demo-tenant",
        name: "New Vendor",
        owner: "Security",
        category: "security",
        risk_level: "medium",
        lifecycle_state: "in_review",
      }),
    });
    expect(created?.status).toBe(201);
    expect(parseFixture(created!)).toMatchObject({
      vendor: {
        name: "New Vendor",
        owner: "Security",
        owner_state: "assigned",
        risk_level: "medium",
        lifecycle_state: "in_review",
      },
    });

    const filtered = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/vendors",
      searchParams: new URLSearchParams("q=New Vendor"),
    });
    expect(parseFixture(filtered!)).toMatchObject({
      summary: { total_vendors: 1 },
      vendors: [expect.objectContaining({ name: "New Vendor" })],
    });
  });

  it("returns source-backed vendor discovery fixtures", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({ method: "GET", path: "grc/vendor-discoveries" });
    expect(response?.status).toBe(200);
    expect(parseFixture(response!)).toMatchObject({
      summary: { total_discoveries: 4, discovered: 3, linked: 1, source_count: 3, evidence_signals: 6 },
      source_summaries: expect.arrayContaining([
        expect.objectContaining({ source_id: "okta", provider: "Okta", total: 2, discovered: 2 }),
        expect.objectContaining({ source_id: "github", provider: "GitHub", total: 2 }),
        expect.objectContaining({ source_id: "aws", provider: "AWS", total: 1, linked: 1 }),
      ]),
      discoveries: expect.arrayContaining([
        expect.objectContaining({
          name: "Design Suite",
          source_id: "okta",
          confidence_score: 92,
          signals: expect.arrayContaining([
            expect.objectContaining({ source_id: "okta", label: "Okta application assignment" }),
          ]),
        }),
      ]),
    });

    const oktaFiltered = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/vendor-discoveries",
      searchParams: new URLSearchParams("source_id=okta"),
    });
    expect(parseFixture(oktaFiltered!)).toMatchObject({
      summary: { total_discoveries: 2, source_count: 1 },
      discoveries: [
        expect.objectContaining({ source_id: "okta" }),
        expect.objectContaining({ source_id: "okta" }),
      ],
    });

    const signalSearch = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/vendor-discoveries",
      searchParams: new URLSearchParams("q=marketplace"),
    });
    expect(parseFixture(signalSearch!)).toMatchObject({
      discoveries: [expect.objectContaining({ name: "Data Warehouse" })],
    });
  });

  it("runs vendor discovery sync fixtures", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/vendor-discoveries/sync",
      body: JSON.stringify({ source_id: "okta" }),
    });
    expect(response?.status).toBe(200);
    expect(parseFixture(response!)).toMatchObject({
      status: "completed",
      source_id: "okta",
      source_summaries: [expect.objectContaining({ source_id: "okta", total: 2 })],
    });
  });

  it("updates vendor fixtures through quick actions", () => {
    withFixtureMode();
    const vendorURN = "urn:cerebro:demo-tenant:vendor:payments-processor";
    const response = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/vendors/${encodeURIComponent(vendorURN)}/actions`,
      body: JSON.stringify({ action: "assign_owner", owner: "Finance" }),
    });
    expect(response?.status).toBe(200);
    expect(parseFixture(response!)).toMatchObject({
      action: "assign_owner",
      vendor: {
        name: "Payments Processor",
        owner: "Finance",
        owner_state: "assigned",
      },
    });

    resetCerebroFixtureStateForTests();
    const resetResponse = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/vendors",
      searchParams: new URLSearchParams("q=payments"),
    });
    expect(parseFixture(resetResponse!)).toMatchObject({
      vendors: [expect.objectContaining({
        name: "Payments Processor",
        owner_state: "missing",
      })],
    });
    expect(parseFixture(resetResponse!).vendors[0].owner).toBeUndefined();
  });

  it("returns and mutates unified questionnaire run fixtures", () => {
    withFixtureMode();
    const list = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/questionnaire-runs",
    });
    expect(list?.status).toBe(200);
    expect(parseFixture(list!)).toMatchObject({
      summary: {
        total_runs: 2,
        blocked_answers: 1,
        review_answers: 3,
        ready_answers: 2,
        stale_evidence: 2,
      },
      runs: [
        expect.objectContaining({ direction: "customer_security_review" }),
        expect.objectContaining({ direction: "vendor_review" }),
      ],
    });

    const vendorList = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/questionnaire-runs",
      searchParams: new URLSearchParams({ direction: "vendor_review", vendor_urn: "urn:cerebro:demo-tenant:vendor:core-sso" }),
    });
    expect(parseFixture(vendorList!)).toMatchObject({
      summary: { total_runs: 1, vendor_runs: 1 },
      runs: [expect.objectContaining({ run_id: "vendor-review-core-sso-2026" })],
    });

    const decision = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/questionnaire-runs/customer-review-acme-2026/decisions",
      body: JSON.stringify({ state: "approved", reason: "Answers accepted." }),
    });
    expect(parseFixture(decision!)).toMatchObject({
      run: { run_id: "customer-review-acme-2026", status: "needs_input", decision: "approved" },
    });

    const conditionalDecision = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/questionnaire-runs/vendor-review-core-sso-2026/decisions",
      body: JSON.stringify({ state: "approved_with_conditions", reason: "Refresh MFA proof before renewal." }),
    });
    expect(parseFixture(conditionalDecision!)).toMatchObject({
      run: { run_id: "vendor-review-core-sso-2026", status: "approved", decision: "approved_with_conditions" },
    });

    const created = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/questionnaire-runs",
      body: JSON.stringify({
        direction: "customer_security_review",
        title: "New customer questionnaire",
        customer_name: "NewCo",
        source_format: "csv",
        intake_text: "section,question,required_evidence_slots\nAccess,Do you enforce MFA?,identity_mfa\nAudit,Attach the SOC 2 report.,audit_report",
      }),
    });
    expect(created?.status).toBe(201);
    const createdPayload = parseFixture(created!);
    expect(createdPayload).toMatchObject({
      run: { title: "New customer questionnaire", question_count: 2, unassigned_count: 2 },
    });

    const portalCreated = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/questionnaire-runs",
      body: JSON.stringify({
        direction: "customer_security_review",
        title: "Portal questionnaire",
        source_format: "portal",
        intake_format: "portal",
        portal_url: "https://portal.example.com/review/123",
        portal_instructions: "Use SSO and assign missing access to sales ops.",
        intake_text: "Access:\nQuestion 1: Do you enforce MFA?\nSave\nAudit:\nQuestion: Attach the SOC 2 report.",
      }),
    });
    expect(portalCreated?.status).toBe(201);
    expect(parseFixture(portalCreated!)).toMatchObject({
      run: {
        title: "Portal questionnaire",
        question_count: 2,
        questions: expect.arrayContaining([
          expect.objectContaining({ question: "Do you enforce MFA?", section: "Access" }),
          expect.objectContaining({ question: "Attach the SOC 2 report.", section: "Audit" }),
        ]),
        attributes: {
          intake_format: "portal",
          portal_url: "https://portal.example.com/review/123",
          portal_status: "questions_captured",
          portal_instructions: "Use SSO and assign missing access to sales ops.",
        },
      },
    });

    const portalCapture = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/questionnaire-runs",
      body: JSON.stringify({
        direction: "customer_security_review",
        title: "Portal capture",
        source_format: "portal",
        intake_format: "portal",
        portal_url: "https://portal.example.com/review/456",
        portal_instructions: "Waiting on portal access.",
      }),
    });
    expect(portalCapture?.status).toBe(201);
    const portalCapturePayload = parseFixture(portalCapture!);
    expect(portalCapturePayload).toMatchObject({
      run: {
        title: "Portal capture",
        question_count: 0,
        status: "intake",
        attributes: {
          intake_format: "portal",
          portal_url: "https://portal.example.com/review/456",
          portal_status: "needs_capture",
        },
      },
    });

    const portalCaptureRun = portalCapturePayload.run as { run_id: string };
    const portalAssignment = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/questionnaire-runs/${portalCaptureRun.run_id}/assignments`,
      body: JSON.stringify({ owner_id: "sales-ops@example.com", reason: "Capture portal questions." }),
    });
    expect(parseFixture(portalAssignment!)).toMatchObject({
      run: {
        assignments: [expect.objectContaining({ owner_id: "sales-ops@example.com", question_id: "" })],
      },
    });

    const portalComment = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/questionnaire-runs/${portalCaptureRun.run_id}/comments`,
      body: JSON.stringify({ body: "Portal access requested." }),
    });
    expect(parseFixture(portalComment!)).toMatchObject({
      run: {
        comments: [expect.objectContaining({ body: "Portal access requested.", question_id: "" })],
      },
    });

    const createdRun = createdPayload.run as { run_id: string };
    const mapped = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/questionnaire-runs/${createdRun.run_id}/questions`,
      body: JSON.stringify({
        question_id: "fixture-question-1",
        required_evidence_slots: ["identity_mfa", "policy"],
        mapped_controls: ["SOC2-CC6.1"],
        owner_id: "security@example.com",
      }),
    });
    expect(parseFixture(mapped!)).toMatchObject({
      run: {
        questions: expect.arrayContaining([expect.objectContaining({
          id: "fixture-question-1",
          required_evidence_slots: ["identity_mfa", "policy"],
          mapped_controls: ["SOC2-CC6.1"],
          owner_id: "security@example.com",
        })]),
        timeline: expect.arrayContaining([expect.objectContaining({ event_type: "updated" })]),
      },
    });

    const linked = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/questionnaire-runs/${createdRun.run_id}/vendor-link`,
      body: JSON.stringify({
        vendor_urn: "urn:cerebro:demo-tenant:vendor:core-sso",
        reason: "Matched requester.",
      }),
    });
    expect(parseFixture(linked!)).toMatchObject({
      run: {
        direction: "vendor_review",
        vendor_urn: "urn:cerebro:demo-tenant:vendor:core-sso",
        vendor_id: "core-sso",
        attributes: {
          linked_vendor_urn: "urn:cerebro:demo-tenant:vendor:core-sso",
          vendor_link_previous_direction: "customer_security_review",
          vendor_link_status: "linked",
        },
        timeline: expect.arrayContaining([expect.objectContaining({ event_type: "vendor_linked" })]),
      },
    });

    const linkedVendorList = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/questionnaire-runs",
      searchParams: new URLSearchParams({ direction: "vendor_review", vendor_urn: "urn:cerebro:demo-tenant:vendor:core-sso" }),
    });
    expect(parseFixture(linkedVendorList!)).toMatchObject({
      summary: { total_runs: 2, vendor_runs: 2 },
    });

    const unlinked = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/questionnaire-runs/${createdRun.run_id}/vendor-link`,
      body: JSON.stringify({ unlink: true, reason: "Wrong vendor." }),
    });
    const unlinkedPayload = parseFixture(unlinked!);
    expect(unlinkedPayload).toMatchObject({
      run: {
        direction: "customer_security_review",
        attributes: {
          vendor_link_status: "unlinked",
        },
      },
    });
    expect((unlinkedPayload.run as { vendor_urn?: string }).vendor_urn).toBeUndefined();
    expect((unlinkedPayload.run as { attributes?: Record<string, string> }).attributes?.vendor_link_previous_direction).toBeUndefined();

    const missingVendor = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/questionnaire-runs/${createdRun.run_id}/vendor-link`,
      body: JSON.stringify({ reason: "No selected vendor." }),
    });
    expect(missingVendor?.status).toBe(400);

    const comment = cerebroFixtureResponseFor({
      method: "POST",
      path: `grc/questionnaire-runs/${createdRun.run_id}/comments`,
      body: JSON.stringify({ question_id: "fixture-question-1", body: "Owner asked for current evidence." }),
    });
    expect(parseFixture(comment!)).toMatchObject({
      run: {
        comments: [expect.objectContaining({ body: "Owner asked for current evidence." })],
        timeline: expect.arrayContaining([expect.objectContaining({ event_type: "commented" })]),
      },
    });
  });

  it("returns policy lifecycle records in fixture mode", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({ method: "GET", path: "grc/policy-lifecycle" });
    const payload = parseFixture(response!);
    expect(response?.status).toBe(200);
    expect(payload.summary).toMatchObject({
      policies: 4,
      pending_approvals: 2,
      lifecycle_events: 7,
      governance_gaps: 5,
      open_governance_gaps: 3,
      in_progress_governance_gaps: 1,
      acknowledged_governance_gaps: 1,
    });
    expect(payload.templates).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "tpl-access-control" }),
    ]));
    expect(payload.governance_gaps).toEqual(expect.arrayContaining([
      expect.objectContaining({ subject: "document", subject_id: "retention-standard", reason: "Missing owner", gap_state: "acknowledged", rule_id: "document.owner" }),
      expect.objectContaining({ subject: "risk", subject_id: "risk-incident-escalation", reason: "No evidence", gap_state: "in_progress", action_id: "governance_gap.attach_evidence" }),
    ]));
    expect(payload.governance_rules).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "document.owner", action_id: "governance_gap.assign_owner" }),
    ]));
    expect(payload.governance_gap_rollups.by_state).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: "open", count: 3 }),
    ]));
    expect(payload.available_actions).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "governance_gap.attach_evidence", value_field: "evidence_urns" }),
      expect.objectContaining({ id: "governance_gap.link_policy", value_field: "target_policy_id" }),
    ]));
    expect(payload.work_queue).toEqual(expect.arrayContaining([
      expect.objectContaining({ action: "Approve version" }),
    ]));
    expect(payload.events).toEqual(expect.arrayContaining([
      expect.objectContaining({ action: "approval.request" }),
    ]));
    expect(payload.reminder_plan).toEqual(expect.arrayContaining([
      expect.objectContaining({ action: "Exception renewal" }),
    ]));
  });

  it("returns policy lifecycle action and export fixtures", () => {
    withFixtureMode();
    const actionResponse = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/policy-lifecycle/actions",
      body: JSON.stringify({ action: "approval.approve", policy_id: "access-control", policy_version_id: "access-control-2.1" }),
    });
    expect(actionResponse?.status).toBe(200);
    expect(parseFixture(actionResponse!)).toMatchObject({ action: "approval.approve", status: "accepted" });

    const exportResponse = cerebroFixtureResponseFor({ method: "GET", path: "grc/policy-lifecycle/export" });
    expect(exportResponse?.headers["content-type"]).toContain("text/csv");
    expect(exportResponse?.body).toContain("policy.version");
  });

  it("returns packaged evidence workflow fixtures", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/evidence-packets",
      searchParams: new URLSearchParams("limit=2"),
    });
    const payload = parseFixture(response!);

    expect(response?.status).toBe(200);
    expect(payload).toMatchObject({
      program: { id: "fixture-evidence-program", evidence_item_count: 2 },
      evidence_requests: expect.arrayContaining([
        expect.objectContaining({ id: "fixture-request-1", review_status: "needs_review" }),
      ]),
      controls: expect.arrayContaining([
        expect.objectContaining({ id: "fixture-control-cc6-1", evidence_request_ids: ["fixture-request-1"] }),
      ]),
      collection_sources: expect.arrayContaining([
        expect.objectContaining({ source_id: "okta", status: "collected" }),
      ]),
      evidence_lineage: expect.arrayContaining([
        expect.objectContaining({ evidence_id: "demo-evidence-identity-mfa", evidence_packet_ids: ["fixture-packet-1"] }),
      ]),
      questionnaire_answers: expect.arrayContaining([
        expect.objectContaining({ id: "acme-a-mfa", evidence_packet_ids: ["fixture-packet-1"] }),
      ]),
    });
    expect(payload.evidence_items).toHaveLength(2);
  });

  it("filters control packet fixtures by framework query", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/control-packets",
      searchParams: new URLSearchParams("framework=ISO%2027001"),
    });
    const payload = parseFixture(response!);

    expect(response?.status).toBe(200);
    expect(payload.packet).toMatchObject({ summary: { total: 1 } });
    expect(payload.controls).toEqual([
      expect.objectContaining({ framework_id: "iso27001", control_id: "A.5.15" }),
    ]);
  });

  it("returns asset detail fixtures for encoded URNs", () => {
    withFixtureMode();
    const urn = "urn:cerebro:demo-tenant:repository:public-demo";
    const response = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/inventory/assets/detail",
      searchParams: new URLSearchParams({ urn }),
    });
    const payload = parseFixture(response!);
    expect(payload.asset).toMatchObject({ urn, label: "public-demo" });
  });

  it("returns empty report runs in fixture mode", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({ method: "GET", path: "report-runs" });
    expect(response?.status).toBe(200);
    expect(parseFixture(response!)).toMatchObject({ runs: [] });
  });

  it("acknowledges write fixtures without a live backend", () => {
    withFixtureMode();
    const response = cerebroFixtureResponseFor({
      method: "POST",
      path: "grc/inventory/resource-scope",
      body: JSON.stringify({ asset_urn: "urn:cerebro:demo-tenant:service:payments-api", scope_state: "out_of_scope" }),
    });
    const payload = parseFixture(response!);
    expect(response?.status).toBe(200);
    expect(payload.scope).toMatchObject({ scope_state: "out_of_scope" });
  });

  it("returns and saves user preference fixtures", () => {
    withFixtureMode();
    const initial = cerebroFixtureResponseFor({ method: "GET", path: "user/preferences" });
    expect(parseFixture(initial!)).toMatchObject({ persisted: false, preferences: {} });

    const saved = cerebroFixtureResponseFor({
      method: "PUT",
      path: "user/preferences",
      body: JSON.stringify({ preferences: { display: { density: "compact", theme: "dark" } } }),
    });
    const payload = parseFixture(saved!);
    expect(saved?.status).toBe(200);
    expect(payload).toMatchObject({
      persisted: true,
      user_id: "local-developer",
      preferences: { display: { density: "compact", theme: "dark" } },
    });
  });
});
