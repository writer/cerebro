// Same handler as /api/auth/oidc/callback, mounted at the AWS ALB OIDC callback path so an IdP app that was
// registered for the ALB keeps working when CEREBRO_SSO_OIDC_CALLBACK_PATH selects it.
export { GET } from "@/app/api/auth/oidc/callback/route";
