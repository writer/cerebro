import type { Metadata } from "next";

import CerebroMark from "@/components/brand/CerebroMark";
import LoginForm, { type LoginConnectionOption } from "@/components/auth/LoginForm";
import { getCachedSsoConnections, identityApiConfigured } from "@/lib/sso/policy";
import { sanitizeReturnTo } from "@/lib/sso/return-to";
import { LOGIN_ERROR_CODES, type LoginErrorCode } from "@/lib/sso/types";

export const metadata: Metadata = {
  title: "Sign in · Cerebro",
};

const ERROR_MESSAGES: Record<LoginErrorCode, string> = {
  access_denied: "Your identity provider did not allow this sign-in. Ask your administrator for access.",
  domain_not_allowed: "That email domain isn't set up for single sign-on. Use your work email, or ask your administrator.",
  not_provisioned: "Your account hasn't been provisioned for Cerebro yet. Ask your administrator to assign you the app.",
  expired: "Your sign-in took too long or was started in another browser. Please try again.",
  invalid_response: "We couldn't verify the response from your identity provider. Please try again.",
  misconfigured: "Single sign-on isn't configured correctly. Contact your administrator.",
};

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value);

const loadConnections = async (): Promise<{ connections: LoginConnectionOption[]; unavailable: boolean }> => {
  if (!identityApiConfigured()) return { connections: [], unavailable: false };
  try {
    const connections = await getCachedSsoConnections();
    return {
      connections: connections
        .filter((connection) => connection.status === "active")
        .map((connection) => ({ id: connection.id, name: connection.name })),
      unavailable: false,
    };
  } catch {
    return { connections: [], unavailable: true };
  }
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const returnTo = sanitizeReturnTo(first(params.returnTo));
  const errorCode = first(params.error);
  const error = LOGIN_ERROR_CODES.includes(errorCode as LoginErrorCode) ? ERROR_MESSAGES[errorCode as LoginErrorCode] : null;
  const preferredConnection = first(params.connection) ?? "";
  const test = first(params.test) === "1";
  const { connections, unavailable } = await loadConnections();

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--background)] px-4 py-12">
      <div className="w-full max-w-[400px]">
        <div className="surface-raised rounded-2xl p-8 max-sm:p-6">
          <div className="flex flex-col items-center text-center">
            <CerebroMark title="Cerebro" className="h-12 w-12 drop-shadow-[0_6px_12px_rgba(79,70,229,0.45)]" />
            <h1 className="mt-5 text-[22px] font-semibold tracking-[-0.01em] text-[var(--text-primary)]">Sign in to Cerebro</h1>
            <p className="mt-1.5 text-[13px] text-[var(--text-muted)]">
              {test ? "Testing a single sign-on connection." : "Use your organization's single sign-on."}
            </p>
          </div>

          {error && (
            <div
              role="alert"
              className="mt-6 rounded-lg border border-rose-300 bg-rose-50 px-3.5 py-3 text-[13px] leading-5 text-rose-900 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-100"
            >
              {error}
            </div>
          )}

          {unavailable && (
            <div
              role="status"
              className="mt-6 rounded-lg border border-amber-300 bg-amber-50 px-3.5 py-3 text-[13px] leading-5 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100"
            >
              Sign-in options could not be loaded. You can still continue with your work email.
            </div>
          )}

          <LoginForm
            connections={connections}
            preferredConnectionId={preferredConnection}
            returnTo={returnTo}
            test={test}
          />
        </div>
        <p className="mt-6 text-center text-[12px] text-[var(--text-muted)]">
          Access is managed by your organization&apos;s identity provider.
        </p>
      </div>
    </div>
  );
}
