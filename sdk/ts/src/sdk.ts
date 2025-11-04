import HttpClient, { HttpClientOptions } from "./httpClient";
import { AnalyticsClient } from "./clients/analytics";
import { AgentsClient } from "./clients/agents";
import { AuthClient } from "./clients/auth";
import { FindingsClient } from "./clients/findings";
import { IntegrationsClient } from "./clients/integrations";
import { OrganizationsClient } from "./clients/organizations";
import { SecurityCenterClient } from "./clients/securityCenter";

export interface CerebroSDKOptions extends HttpClientOptions {}

export class CerebroSDK {
  private readonly http: HttpClient;
  private readonly analyticsClient: AnalyticsClient;
  private readonly agentsClient: AgentsClient;
  private readonly authClient: AuthClient;
  private readonly findingsClient: FindingsClient;
  private readonly integrationsClient: IntegrationsClient;
  private readonly organizationsClient: OrganizationsClient;
  private readonly securityCenterClient: SecurityCenterClient;

  constructor(options: CerebroSDKOptions) {
    this.http = new HttpClient(options);
    this.analyticsClient = new AnalyticsClient(this.http);
    this.agentsClient = new AgentsClient(this.http);
    this.authClient = new AuthClient(this.http);
    this.findingsClient = new FindingsClient(this.http);
    this.integrationsClient = new IntegrationsClient(this.http);
    this.organizationsClient = new OrganizationsClient(this.http);
    this.securityCenterClient = new SecurityCenterClient(this.http);
  }

  get analytics(): AnalyticsClient {
    return this.analyticsClient;
  }

  get agents(): AgentsClient {
    return this.agentsClient;
  }

  get auth(): AuthClient {
    return this.authClient;
  }

  get findings(): FindingsClient {
    return this.findingsClient;
  }

  get integrations(): IntegrationsClient {
    return this.integrationsClient;
  }

  get organizations(): OrganizationsClient {
    return this.organizationsClient;
  }

  get securityCenter(): SecurityCenterClient {
    return this.securityCenterClient;
  }

  get baseUrl(): string {
    return this.http.base;
  }
}

export default CerebroSDK;
