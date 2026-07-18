import { parseSecurityProducers } from "@/lib/security-producers";

export const runtimeSecurityProducers = () =>
  parseSecurityProducers(process.env.CEREBRO_SECURITY_PRODUCERS_JSON);
