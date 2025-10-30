import HttpClient, { HttpClientOptions } from "./httpClient";
import { AnalyticsClient } from "./clients/analytics";
import { AgentsClient } from "./clients/agents";
import { IntegrationsClient } from "./clients/integrations";

export interface CerebroSDKOptions extends HttpClientOptions {}

export class CerebroSDK {
  private readonly http: HttpClient;
  private readonly analyticsClient: AnalyticsClient;
  private readonly agentsClient: AgentsClient;
  private readonly integrationsClient: IntegrationsClient;

  constructor(options: CerebroSDKOptions) {
    this.http = new HttpClient(options);
    this.analyticsClient = new AnalyticsClient(this.http);
    this.agentsClient = new AgentsClient(this.http);
    this.integrationsClient = new IntegrationsClient(this.http);
  }

  get analytics(): AnalyticsClient {
    return this.analyticsClient;
  }

  get agents(): AgentsClient {
    return this.agentsClient;
  }

  get integrations(): IntegrationsClient {
    return this.integrationsClient;
  }

  get baseUrl(): string {
    return this.http.base;
  }
}

export default CerebroSDK;
