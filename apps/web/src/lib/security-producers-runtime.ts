import { parseSecurityProducerCatalog } from "@/lib/security-producers";

export const runtimeSecurityProducerCatalog = () =>
  parseSecurityProducerCatalog(process.env.CEREBRO_SECURITY_PRODUCERS_JSON);
