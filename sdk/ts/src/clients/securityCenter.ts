import HttpClient from "../httpClient.js";
import { toCustomerMetadataEnvelope, toVendorMetadataEnvelope } from "../metadata.js";
import { CustomerMetadataEnvelope, VendorMetadataEnvelope } from "../types.js";

const parseDate = (value: unknown): Date | null => {
  if (!value) {
    return null;
  }
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const toRecord = (value: unknown): Record<string, unknown> | null => {
  if (!value || typeof value !== "object") {
    return null;
  }
  return value as Record<string, unknown>;
};

const safeVendorEnvelope = (raw: Record<string, unknown> | null): VendorMetadataEnvelope | null => {
  if (!raw) return null;
  try {
    return toVendorMetadataEnvelope(raw);
  } catch {
    return null;
  }
};

const safeCustomerEnvelope = (raw: Record<string, unknown> | null): CustomerMetadataEnvelope | null => {
  if (!raw) return null;
  try {
    return toCustomerMetadataEnvelope(raw);
  } catch {
    return null;
  }
};

export interface RegisterVendorRequest {
  name: string;
  websiteUrl: string;
  category: string;
  primaryContact?: string;
  industry?: string;
  country?: string;
  dataProcessingLocations?: string[];
  certifications?: string[];
  dataTypesProcessed?: string[];
  businessCriticality?: string;
  annualSpend?: number;
}

export interface VendorRegistrationSummary {
  vendorId: string;
  name: string;
  riskLevel: string;
  riskScore: number;
  nextReviewDue: Date | null;
  message: string;
}

export interface RegisterCustomerRequest {
  name: string;
  accountManager: string;
  segment: string;
  primaryContact?: string;
  industry?: string;
  region?: string;
  seatsCommitted?: number;
  annualRecurringRevenue?: number;
  adoptionMetrics?: Record<string, number>;
  supportTicketsOpen?: number;
  lifecycleStage?: string;
  lastEngagementAt?: Date | string;
  nextQbrAt?: Date | string;
  metadata?: Record<string, unknown>;
  successPrograms?: string[];
}

export interface CustomerRegistrationSummary {
  customerId: string;
  lifecycleStage: string;
}

export interface SecurityCenterMetric {
  label: string;
  value: number | string;
  trend: string;
}

export interface SecurityCenterRecentActivity {
  name: string;
  status: string;
  timestamp: string;
}

export interface SecurityCenterUpcomingExpiration {
  control: string;
  owner: string;
  due: string;
}

export interface SecurityCenterSubmissionSummary {
  id: string;
  documentId: string;
  question: string;
  ownerEmail: string;
  ownerTeam: string;
  submittedAt: Date | null;
  status: string;
  knowledgeBaseType: string;
  infoSecApprover?: string | null;
  dueDate: Date | null;
  requiresApproval: boolean;
  autoReleaseEligible: boolean;
  kbSummary?: string | null;
  requesterEmail?: string | null;
}

export interface SecurityCenterVendorInsight {
  vendorId: string;
  name: string;
  category: string;
  riskLevel: string;
  inherentRiskScore: number;
  residualRiskScore: number;
  lifecycleStage: string;
  nextReviewDue: Date | null;
  businessCriticality: string;
  metadata: VendorMetadataEnvelope | null;
  rawMetadata: Record<string, unknown> | null;
}

export interface SecurityCenterCustomerInsight {
  customerId: string;
  name: string;
  segment: string;
  healthBand: string;
  healthScore: number;
  churnRiskScore: number;
  lifecycleStage: string;
  accountManager: string;
  nextQbrAt: Date | null;
  lastEngagementAt: Date | null;
  metadata: CustomerMetadataEnvelope | null;
  rawMetadata: Record<string, unknown> | null;
}

export interface SecurityCenterOverview {
  metrics: SecurityCenterMetric[];
  recentActivity: SecurityCenterRecentActivity[];
  upcomingExpirations: SecurityCenterUpcomingExpiration[];
  submissions: SecurityCenterSubmissionSummary[];
  vendorInsights: SecurityCenterVendorInsight[];
  customerInsights: SecurityCenterCustomerInsight[];
}

export interface SecurityCenterVendorList {
  count: number;
  vendors: SecurityCenterVendorInsight[];
}

export interface SecurityCenterCustomerList {
  count: number;
  customers: SecurityCenterCustomerInsight[];
}

interface VendorRegistrationPayload {
  success?: boolean;
  message?: string;
  data?: {
    vendor_id?: string;
    name?: string;
    risk_level?: string;
    risk_score?: number;
    next_review_due?: string | null;
  };
}

interface CustomerRegistrationPayload {
  success?: boolean;
  customer_id?: string;
  lifecycle_stage?: string;
}

interface OverviewPayload {
  metrics: Array<{ label: string; value: number | string; trend: string }>;
  recentActivity: Array<{ name: string; status: string; timestamp: string }>;
  upcomingExpirations: Array<{ control: string; owner: string; due: string }>;
  submissions: Array<{
    id: string;
    documentId: string;
    question: string;
    ownerEmail: string;
    ownerTeam: string;
    submittedAt: string | null;
    status: string;
    knowledgeBaseType: string;
    infoSecApprover?: string | null;
    dueDate?: string | null;
    requiresApproval: boolean;
    autoReleaseEligible: boolean;
    kbSummary?: string | null;
    requesterEmail?: string | null;
  }>;
  vendorInsights: VendorInsightPayload[];
  customerInsights: CustomerInsightPayload[];
}

interface VendorInsightPayload {
  vendorId: string;
  name: string;
  category: string;
  riskLevel: string;
  inherentRiskScore: number;
  residualRiskScore: number;
  lifecycleStage: string;
  nextReviewDue: string | null;
  businessCriticality: string;
  metadata?: Record<string, unknown> | null;
}

interface CustomerInsightPayload {
  customerId: string;
  name: string;
  segment: string;
  healthBand: string;
  healthScore: number;
  churnRiskScore: number;
  lifecycleStage: string;
  accountManager: string;
  nextQbrAt: string | null;
  lastEngagementAt: string | null;
  metadata?: Record<string, unknown> | null;
}

interface VendorListPayload {
  count: number;
  vendors: VendorInsightPayload[];
}

interface CustomerListPayload {
  count: number;
  customers: CustomerInsightPayload[];
}

export class SecurityCenterClient {
  constructor(private readonly http: HttpClient) {}

  async registerVendor(orgId: string, request: RegisterVendorRequest): Promise<VendorRegistrationSummary> {
    const payload = await this.http.post<VendorRegistrationPayload>(
      `/api/v1/vendors/organizations/${orgId}/vendors`,
      {
        body: this.buildVendorBody(request),
      },
    );

    const data = payload.data ?? {};
    return {
      vendorId: String(data.vendor_id ?? ""),
      name: String(data.name ?? request.name),
      riskLevel: String(data.risk_level ?? ""),
      riskScore: Number(data.risk_score ?? 0),
      nextReviewDue: parseDate(data.next_review_due),
      message: payload.message ?? "",
    };
  }

  async registerCustomer(orgId: string, request: RegisterCustomerRequest): Promise<CustomerRegistrationSummary> {
    const payload = await this.http.post<CustomerRegistrationPayload>(
      `/api/v1/customers/organizations/${orgId}/customers`,
      {
        body: this.buildCustomerBody(request),
      },
    );

    return {
      customerId: String(payload.customer_id ?? ""),
      lifecycleStage: String(payload.lifecycle_stage ?? request.lifecycleStage ?? ""),
    };
  }

  async getOverview(orgId: string): Promise<SecurityCenterOverview> {
    const payload = await this.http.get<OverviewPayload>(
      `/api/v1/security-center/organizations/${orgId}/overview`,
    );

    return {
      metrics: payload.metrics.map((entry) => ({
        label: entry.label,
        value: entry.value,
        trend: entry.trend,
      })),
      recentActivity: payload.recentActivity.map((entry) => ({
        name: entry.name,
        status: entry.status,
        timestamp: entry.timestamp,
      })),
      upcomingExpirations: payload.upcomingExpirations.map((entry) => ({
        control: entry.control,
        owner: entry.owner,
        due: entry.due,
      })),
      submissions: payload.submissions.map(mapSubmissionSummary),
      vendorInsights: payload.vendorInsights.map(mapVendorInsight),
      customerInsights: payload.customerInsights.map(mapCustomerInsight),
    };
  }

  async listVendors(orgId: string): Promise<SecurityCenterVendorList> {
    const payload = await this.http.get<VendorListPayload>(
      `/api/v1/security-center/organizations/${orgId}/vendors`,
    );

    return {
      count: payload.count,
      vendors: payload.vendors.map(mapVendorInsight),
    };
  }

  async listCustomers(orgId: string): Promise<SecurityCenterCustomerList> {
    const payload = await this.http.get<CustomerListPayload>(
      `/api/v1/security-center/organizations/${orgId}/customers`,
    );

    return {
      count: payload.count,
      customers: payload.customers.map(mapCustomerInsight),
    };
  }

  private buildVendorBody(request: RegisterVendorRequest): Record<string, unknown> {
    const body: Record<string, unknown> = {
      name: request.name,
      website_url: request.websiteUrl,
      category: request.category,
    };

    if (request.primaryContact !== undefined) body.primary_contact = request.primaryContact;
    if (request.industry !== undefined) body.industry = request.industry;
    if (request.country !== undefined) body.country = request.country;
    if (request.dataProcessingLocations !== undefined) body.data_processing_locations = request.dataProcessingLocations;
    if (request.certifications !== undefined) body.certifications = request.certifications;
    if (request.dataTypesProcessed !== undefined) body.data_types_processed = request.dataTypesProcessed;
    if (request.businessCriticality !== undefined) body.business_criticality = request.businessCriticality;
    if (request.annualSpend !== undefined) body.annual_spend = request.annualSpend;

    return body;
  }

  private buildCustomerBody(request: RegisterCustomerRequest): Record<string, unknown> {
    const body: Record<string, unknown> = {
      name: request.name,
      account_manager: request.accountManager,
      segment: request.segment,
    };

    if (request.primaryContact !== undefined) body.primary_contact = request.primaryContact;
    if (request.industry !== undefined) body.industry = request.industry;
    if (request.region !== undefined) body.region = request.region;
    if (request.seatsCommitted !== undefined) body.seats_committed = request.seatsCommitted;
    if (request.annualRecurringRevenue !== undefined) body.annual_recurring_revenue = request.annualRecurringRevenue;
    if (request.adoptionMetrics !== undefined) body.adoption_metrics = request.adoptionMetrics;
    if (request.supportTicketsOpen !== undefined) body.support_tickets_open = request.supportTicketsOpen;
    if (request.lifecycleStage !== undefined) body.lifecycle_stage = request.lifecycleStage;
    if (request.lastEngagementAt !== undefined)
      body.last_engagement_at = this.formatDateInput(request.lastEngagementAt);
    if (request.nextQbrAt !== undefined) body.next_qbr_at = this.formatDateInput(request.nextQbrAt);
    if (request.metadata !== undefined) body.metadata = request.metadata;
    if (request.successPrograms !== undefined) body.success_programs = request.successPrograms;

    return body;
  }

  private formatDateInput(value: Date | string): string {
    if (value instanceof Date) {
      return value.toISOString();
    }
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString();
  }
}

const mapSubmissionSummary = (entry: OverviewPayload["submissions"][number]): SecurityCenterSubmissionSummary => ({
  id: entry.id,
  documentId: entry.documentId,
  question: entry.question,
  ownerEmail: entry.ownerEmail,
  ownerTeam: entry.ownerTeam,
  submittedAt: parseDate(entry.submittedAt),
  status: entry.status,
  knowledgeBaseType: entry.knowledgeBaseType,
  infoSecApprover: entry.infoSecApprover ?? null,
  dueDate: parseDate(entry.dueDate ?? null),
  requiresApproval: Boolean(entry.requiresApproval),
  autoReleaseEligible: Boolean(entry.autoReleaseEligible),
  kbSummary: entry.kbSummary ?? null,
  requesterEmail: entry.requesterEmail ?? null,
});

const mapVendorInsight = (entry: VendorInsightPayload): SecurityCenterVendorInsight => {
  const rawMetadata = toRecord(entry.metadata);
  return {
    vendorId: entry.vendorId,
    name: entry.name,
    category: entry.category,
    riskLevel: entry.riskLevel,
    inherentRiskScore: entry.inherentRiskScore,
    residualRiskScore: entry.residualRiskScore,
    lifecycleStage: entry.lifecycleStage,
    nextReviewDue: parseDate(entry.nextReviewDue),
    businessCriticality: entry.businessCriticality,
    metadata: safeVendorEnvelope(rawMetadata),
    rawMetadata,
  };
};

const mapCustomerInsight = (entry: CustomerInsightPayload): SecurityCenterCustomerInsight => {
  const rawMetadata = toRecord(entry.metadata);
  return {
    customerId: entry.customerId,
    name: entry.name,
    segment: entry.segment,
    healthBand: entry.healthBand,
    healthScore: entry.healthScore,
    churnRiskScore: entry.churnRiskScore,
    lifecycleStage: entry.lifecycleStage,
    accountManager: entry.accountManager,
    nextQbrAt: parseDate(entry.nextQbrAt),
    lastEngagementAt: parseDate(entry.lastEngagementAt),
    metadata: safeCustomerEnvelope(rawMetadata),
    rawMetadata,
  };
};
