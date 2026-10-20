"use client";

import { ArrowRight, KeyRound } from "lucide-react";
import { useState, type FormEvent } from "react";

export type LoginConnectionOption = {
  id: string;
  name: string;
};

export const ssoStartHref = (params: Record<string, string | undefined>) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value) search.set(key, value);
  }
  return `/api/auth/sso/start?${search.toString()}`;
};

/**
 * Sign-in starts with a top-level navigation rather than a form submission: CSP `form-action 'self'` also
 * governs where a submitted form may be redirected, and the start endpoint redirects to the IdP.
 */
export default function LoginForm({
  connections,
  preferredConnectionId,
  returnTo,
  test,
}: {
  connections: LoginConnectionOption[];
  preferredConnectionId: string;
  returnTo: string;
  test: boolean;
}) {
  const [email, setEmail] = useState("");
  const [pending, setPending] = useState(false);
  const shared = {
    returnTo: returnTo !== "/" ? returnTo : undefined,
    test: test ? "1" : undefined,
  };
  const ordered = [...connections].sort((left, right) => {
    if (left.id === preferredConnectionId) return -1;
    if (right.id === preferredConnectionId) return 1;
    return left.name.localeCompare(right.name);
  });

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const value = email.trim();
    if (!value) return;
    setPending(true);
    window.location.assign(ssoStartHref({ email: value, ...shared }));
  };

  return (
    <div className="mt-6">
      <form onSubmit={submit} className="space-y-3" noValidate>
        <label htmlFor="login-email" className="block text-[12px] font-medium text-[var(--text-secondary)]">
          Work email
        </label>
        <input
          id="login-email"
          type="email"
          name="email"
          autoComplete="username"
          autoFocus
          required
          placeholder="you@company.com"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          className="control-input w-full px-3.5 py-2.5 text-[14px]"
        />
        <button
          type="submit"
          disabled={pending || !email.trim()}
          className="primary-button w-full px-4 py-2.5 text-[14px] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {pending ? "Redirecting..." : "Continue"}
          {!pending && <ArrowRight className="h-4 w-4" aria-hidden />}
        </button>
      </form>

      {ordered.length > 0 && (
        <>
          <div className="my-6 flex items-center gap-3 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            <span className="h-px flex-1 bg-[var(--border)]" />
            or
            <span className="h-px flex-1 bg-[var(--border)]" />
          </div>
          <ul className="space-y-2.5">
            {ordered.map((connection) => (
              <li key={connection.id}>
                <a
                  href={ssoStartHref({ connection: connection.id, ...shared })}
                  onClick={() => setPending(true)}
                  className="secondary-button w-full px-4 py-2.5 text-[14px]"
                >
                  <KeyRound className="h-4 w-4 text-[var(--text-muted)]" aria-hidden />
                  Continue with {connection.name}
                </a>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
