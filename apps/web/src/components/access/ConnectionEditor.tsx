"use client";

import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, Loader2, Plus, Trash2, X } from "lucide-react";
import { useState } from "react";

import {
  connectionPayload,
  emptyOidcSettings,
  emptySamlSettings,
  identityAdminFetch,
  jsonBody,
  parseCertificates,
  parseDomains,
  parseList,
  protocolLabel,
  validateConnectionDraft,
  type ConnectionDraftErrors,
  type SSOConnection,
  type SSOConnectionInput,
  type SSOProtocol,
  type SSOProviderPreset,
  type SSOServiceProviderInfo,
} from "@/lib/sso-admin";

import { CopyField, Field, inputClass, textareaClass, Toggle } from "./fields";

type DiscoverResult = {
  ok: boolean;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  endSessionEndpoint?: string;
  error?: string;
};

type MetadataResult = { idpEntityId: string; idpSsoUrl: string; idpCertificates: string[] };

const setupSteps: Record<SSOProviderPreset["id"], Record<SSOProtocol, string[]>> = {
  okta: {
    oidc: [
      "In Okta Admin, go to Applications → Create App Integration → OIDC → Web Application.",
      "Paste the sign-in redirect URI below, and set Initiate login URI after you save this connection.",
      "Under Sign On → OpenID Connect ID Token, set the groups claim filter (for example, matches regex .*).",
      "Store the client secret in your secret manager and reference it here.",
    ],
    saml: [
      "In Okta Admin, go to Applications → Create App Integration → SAML 2.0.",
      "Paste the single sign-on URL and audience URI below. Name ID format: EmailAddress.",
      "Add attribute statements email and name, and a group attribute statement named groups.",
      "Copy the metadata URL from the Sign On tab and import it below.",
    ],
  },
  entra: {
    oidc: [
      "In Entra ID, go to App registrations → New registration → Web, and paste the redirect URI below.",
      "Add a client secret, store it in your secret manager, and reference it here.",
      "Under Token configuration, add the groups claim.",
    ],
    saml: [
      "In Entra ID, go to Enterprise applications → New application → Create your own → SAML.",
      "Paste the identifier (entity ID) and reply URL (ACS) below.",
      "Add a group claim, then import the federation metadata URL below.",
    ],
  },
  google: {
    oidc: [
      "In Google Cloud Console, create an OAuth client of type Web application and paste the redirect URI below.",
      "Store the client secret in your secret manager and reference it here. Google OIDC does not send groups.",
    ],
    saml: [
      "In Google Admin, go to Apps → Web and mobile apps → Add custom SAML app.",
      "Paste the ACS URL and entity ID below. Name ID: Basic Information → Primary email.",
      "Map group membership to an attribute named groups, then paste the IdP metadata XML below.",
    ],
  },
  other: {
    oidc: ["Create a confidential OIDC web client with the redirect URI below and the openid, email, and profile scopes."],
    saml: ["Create a SAML 2.0 service provider with the ACS URL and entity ID below, and sign assertions."],
  },
};

export function ConnectionEditor({
  connection,
  draft: initialDraft,
  preset,
  roles,
  spInfo,
  onCancel,
  onSaved,
}: {
  connection: SSOConnection | null;
  draft: SSOConnectionInput;
  preset: SSOProviderPreset;
  roles: string[];
  spInfo: SSOServiceProviderInfo | null;
  onCancel: () => void;
  onSaved: (connection: SSOConnection) => void;
}) {
  const [draft, setDraft] = useState<SSOConnectionInput>(initialDraft);
  const [domainsText, setDomainsText] = useState(initialDraft.domains.join(", "));
  const [certsText, setCertsText] = useState(initialDraft.saml?.idpCertificates.join("\n\n") ?? "");
  const [metadataXml, setMetadataXml] = useState("");
  const [errors, setErrors] = useState<ConnectionDraftErrors>({});
  const [showAdvanced, setShowAdvanced] = useState(false);

  const update = (patch: Partial<SSOConnectionInput>) => setDraft((current) => ({ ...current, ...patch }));
  const updateOidc = (patch: Partial<NonNullable<SSOConnectionInput["oidc"]>>) =>
    setDraft((current) => ({ ...current, oidc: { ...(current.oidc ?? emptyOidcSettings()), ...patch } }));
  const updateSaml = (patch: Partial<NonNullable<SSOConnectionInput["saml"]>>) =>
    setDraft((current) => ({ ...current, saml: { ...(current.saml ?? emptySamlSettings()), ...patch } }));

  const setProtocol = (protocol: SSOProtocol) => {
    if (protocol === draft.protocol) return;
    setDraft((current) => {
      const rest = { ...current };
      delete rest.oidc;
      delete rest.saml;
      return protocol === "oidc"
        ? { ...rest, protocol, oidc: emptyOidcSettings(preset.groupsClaim) }
        : { ...rest, protocol, saml: emptySamlSettings() };
    });
    setErrors({});
  };

  const discover = useMutation<DiscoverResult, Error>({
    mutationFn: () => identityAdminFetch<DiscoverResult>("/oidc/discover", { method: "POST", ...jsonBody({ issuer: draft.oidc?.issuer.trim() }) }),
  });

  const importMetadata = useMutation<MetadataResult, Error, { url?: string; xml?: string }>({
    mutationFn: (input) => identityAdminFetch<MetadataResult>("/saml/parse-metadata", { method: "POST", ...jsonBody(input) }),
    onSuccess: (result, input) => {
      updateSaml({
        idpEntityId: result.idpEntityId,
        idpSsoUrl: result.idpSsoUrl,
        idpCertificates: result.idpCertificates,
        ...(input.url ? { idpMetadataUrl: input.url } : {}),
      });
      setCertsText(result.idpCertificates.join("\n\n"));
    },
  });

  const save = useMutation<SSOConnection, Error, SSOConnectionInput>({
    mutationFn: (payload) =>
      connection
        ? identityAdminFetch<SSOConnection>(`/connections/${encodeURIComponent(connection.id)}`, { method: "PUT", ...jsonBody(payload) })
        : identityAdminFetch<SSOConnection>("/connections", { method: "POST", ...jsonBody(payload) }),
    onSuccess: onSaved,
  });

  const submit = () => {
    const next: SSOConnectionInput = {
      ...draft,
      domains: parseDomains(domainsText),
      ...(draft.protocol === "saml" ? { saml: { ...(draft.saml ?? emptySamlSettings()), idpCertificates: parseCertificates(certsText) } } : {}),
    };
    const nextErrors = validateConnectionDraft(next);
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) return;
    save.mutate(connectionPayload(next));
  };

  const steps = setupSteps[preset.id][draft.protocol];
  const roleOptions = roles.length > 0 ? roles : ["cerebro.viewer", "cerebro.admin"];

  return (
    <section className="surface-panel" aria-label={connection ? `Edit ${connection.name}` : "New SSO connection"}>
      <div className="flex items-start justify-between gap-3 border-b border-[color:var(--border)] px-5 py-4">
        <div>
          <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">
            {connection ? `Edit ${connection.name}` : `Connect ${preset.label}`}
          </h2>
          <p className="mt-1 text-[13px] text-[var(--text-muted)]">
            Changing sign-in settings returns the connection to “Not tested” until you test it again.
          </p>
        </div>
        <button type="button" onClick={onCancel} className="secondary-button inline-flex h-8 w-8 items-center justify-center p-0" aria-label="Close editor">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="grid gap-6 p-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.25fr)]">
        <div className="space-y-5">
          <div className="space-y-2">
            <div className="text-[12px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">Protocol</div>
            <div className="inline-flex rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-1" role="radiogroup" aria-label="Protocol">
              {preset.protocols.map((protocol) => (
                <button
                  key={protocol}
                  type="button"
                  role="radio"
                  aria-checked={draft.protocol === protocol}
                  onClick={() => setProtocol(protocol)}
                  className={`h-8 rounded-md px-3 text-[13px] font-semibold transition ${
                    draft.protocol === protocol ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]" : "text-[var(--text-secondary)]"
                  }`}
                >
                  {protocolLabel[protocol]}
                  {protocol === preset.protocols[0] && <span className="ml-1.5 text-[11px] font-medium text-[var(--text-muted)]">recommended</span>}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-4">
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">1. Set up Cerebro in {preset.label}</div>
            <ol className="list-decimal space-y-1.5 pl-5 text-[12px] leading-5 text-[var(--text-secondary)]">
              {steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            {spInfo ? (
              <div className="space-y-3 pt-1">
                {draft.protocol === "oidc" ? (
                  <CopyField label="Sign-in redirect URI" value={spInfo.redirectUri} />
                ) : (
                  <>
                    <CopyField label="Single sign-on URL (ACS)" value={spInfo.acsUrl} />
                    <CopyField label="Audience URI (SP entity ID)" value={spInfo.entityId} />
                    <CopyField label="SP metadata" value={spInfo.metadataUrl} />
                  </>
                )}
                {connection && spInfo.initiateLoginUrl && (
                  <CopyField label="Initiate login URI" value={spInfo.initiateLoginUrl} hint="Lets users start sign-in from the provider's app tile." />
                )}
              </div>
            ) : (
              <p className="text-[12px] text-[var(--text-muted)]">Loading the values to copy…</p>
            )}
          </div>
        </div>

        <div className="space-y-5">
          <div className="text-[13px] font-semibold text-[var(--text-primary)]">2. Connect to {preset.label}</div>
          <Field label="Connection name" error={errors.name} htmlFor="sso-name">
            <input id="sso-name" className={inputClass} value={draft.name} onChange={(event) => update({ name: event.target.value })} placeholder="Okta" />
          </Field>

          {draft.protocol === "oidc" ? (
            <>
              <Field
                label="Issuer URL"
                htmlFor="sso-issuer"
                error={errors.issuer}
                hint={
                  discover.data?.ok ? (
                    <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-300">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Discovery document found.
                    </span>
                  ) : discover.error ? (
                    <span className="text-red-700 dark:text-red-300">{discover.error.message}</span>
                  ) : discover.data && !discover.data.ok ? (
                    <span className="text-red-700 dark:text-red-300">{discover.data.error || "No discovery document at this issuer."}</span>
                  ) : (
                    "For Okta this is your org URL, or an authorization server such as https://your-org.okta.com/oauth2/default."
                  )
                }
              >
                <div className="flex gap-2">
                  <input
                    id="sso-issuer"
                    className={inputClass}
                    value={draft.oidc?.issuer ?? ""}
                    onChange={(event) => updateOidc({ issuer: event.target.value })}
                    placeholder={preset.issuerPlaceholder}
                    spellCheck={false}
                  />
                  <button
                    type="button"
                    onClick={() => discover.mutate()}
                    disabled={!draft.oidc?.issuer.trim() || discover.isPending}
                    className="secondary-button inline-flex h-9 shrink-0 items-center gap-1.5 px-3 text-[13px]"
                  >
                    {discover.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                    Check
                  </button>
                </div>
              </Field>
              <Field label="Client ID" htmlFor="sso-client-id" error={errors.clientId}>
                <input id="sso-client-id" className={inputClass} value={draft.oidc?.clientId ?? ""} onChange={(event) => updateOidc({ clientId: event.target.value })} spellCheck={false} />
              </Field>
              <Field
                label="Client secret reference"
                htmlFor="sso-secret-ref"
                error={errors.clientSecretRef}
                hint="Where the web service reads the secret: env:CEREBRO_SSO_OKTA_CLIENT_SECRET, or aws-sm:<region>/<secret-id>#client_secret when CEREBRO_SSO_AWS_SECRET_PREFIXES allows it. Cerebro stores only this reference."
              >
                <input
                  id="sso-secret-ref"
                  className={`${inputClass} font-mono`}
                  value={draft.oidc?.clientSecretRef ?? ""}
                  onChange={(event) => updateOidc({ clientSecretRef: event.target.value })}
                  placeholder="env:CEREBRO_SSO_OKTA_CLIENT_SECRET"
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>
              <Toggle
                label="Trust email without email_verified"
                description={
                  draft.oidc?.trustEmailClaim ? (
                    <span className="text-amber-700 dark:text-amber-300" role="alert">
                      Warning: sign-ins are linked to directory users by email. Turn this on only if users cannot set or change their own
                      email address at this provider, or someone could sign in as another person.
                    </span>
                  ) : (
                    "Off: sign-in requires the provider to mark the email address as verified (email_verified = true)."
                  )
                }
                checked={draft.oidc?.trustEmailClaim === true}
                onChange={(trustEmailClaim) => updateOidc({ trustEmailClaim })}
              />
            </>
          ) : (
            <>
              <Field label="Identity provider metadata" hint="Import from a metadata URL, or paste the XML. This fills in the fields below.">
                <div className="space-y-2">
                  <div className="flex gap-2">
                    <input
                      className={inputClass}
                      value={draft.saml?.idpMetadataUrl ?? ""}
                      onChange={(event) => updateSaml({ idpMetadataUrl: event.target.value })}
                      placeholder="https://your-org.okta.com/app/…/sso/saml/metadata"
                      aria-label="Metadata URL"
                      spellCheck={false}
                    />
                    <button
                      type="button"
                      className="secondary-button inline-flex h-9 shrink-0 items-center gap-1.5 px-3 text-[13px]"
                      disabled={!draft.saml?.idpMetadataUrl?.trim() || importMetadata.isPending}
                      onClick={() => importMetadata.mutate({ url: draft.saml?.idpMetadataUrl?.trim() })}
                    >
                      {importMetadata.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                      Import
                    </button>
                  </div>
                  <textarea
                    className={textareaClass}
                    rows={3}
                    value={metadataXml}
                    onChange={(event) => setMetadataXml(event.target.value)}
                    placeholder="…or paste <EntityDescriptor> XML"
                    aria-label="Metadata XML"
                    spellCheck={false}
                  />
                  {metadataXml.trim() && (
                    <button
                      type="button"
                      className="secondary-button inline-flex h-8 items-center px-3 text-[12px]"
                      disabled={importMetadata.isPending}
                      onClick={() => importMetadata.mutate({ xml: metadataXml })}
                    >
                      Import pasted XML
                    </button>
                  )}
                  {importMetadata.error && <p className="text-[12px] text-red-700 dark:text-red-300">{importMetadata.error.message}</p>}
                  {importMetadata.isSuccess && (
                    <p className="inline-flex items-center gap-1 text-[12px] text-emerald-700 dark:text-emerald-300">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Imported entity ID, sign-on URL, and {importMetadata.data.idpCertificates.length} certificate(s).
                    </p>
                  )}
                </div>
              </Field>
              <Field label="IdP entity ID (issuer)" htmlFor="sso-idp-entity" error={errors.idpEntityId}>
                <input id="sso-idp-entity" className={inputClass} value={draft.saml?.idpEntityId ?? ""} onChange={(event) => updateSaml({ idpEntityId: event.target.value })} spellCheck={false} />
              </Field>
              <Field label="IdP single sign-on URL" htmlFor="sso-idp-url" error={errors.idpSsoUrl}>
                <input id="sso-idp-url" className={inputClass} value={draft.saml?.idpSsoUrl ?? ""} onChange={(event) => updateSaml({ idpSsoUrl: event.target.value })} spellCheck={false} />
              </Field>
              <Field label="Signing certificates" htmlFor="sso-idp-certs" error={errors.idpCertificates} hint="PEM. Add the next certificate here before your provider rotates it.">
                <textarea id="sso-idp-certs" className={textareaClass} rows={4} value={certsText} onChange={(event) => setCertsText(event.target.value)} spellCheck={false} />
              </Field>
            </>
          )}

          <button type="button" className="text-[12px] font-semibold text-[var(--primary)]" onClick={() => setShowAdvanced((value) => !value)}>
            {showAdvanced ? "Hide" : "Show"} claim and attribute names
          </button>
          {showAdvanced && (
            <div className="grid gap-4 sm:grid-cols-2">
              {draft.protocol === "oidc" ? (
                <>
                  <Field label="Groups claim">
                    <input className={inputClass} value={draft.oidc?.groupsClaim ?? ""} onChange={(event) => updateOidc({ groupsClaim: event.target.value })} />
                  </Field>
                  <Field label="Scopes">
                    <input className={inputClass} value={draft.oidc?.scopes.join(" ") ?? ""} onChange={(event) => updateOidc({ scopes: parseList(event.target.value) })} />
                  </Field>
                </>
              ) : (
                <>
                  <Field label="Email attribute">
                    <input className={inputClass} value={draft.saml?.emailAttribute ?? ""} onChange={(event) => updateSaml({ emailAttribute: event.target.value })} />
                  </Field>
                  <Field label="Name attribute">
                    <input className={inputClass} value={draft.saml?.nameAttribute ?? ""} onChange={(event) => updateSaml({ nameAttribute: event.target.value })} />
                  </Field>
                  <Field label="Groups attribute">
                    <input className={inputClass} value={draft.saml?.groupsAttribute ?? ""} onChange={(event) => updateSaml({ groupsAttribute: event.target.value })} />
                  </Field>
                  <Field label="Name ID format">
                    <input className={inputClass} value={draft.saml?.nameIdFormat ?? ""} onChange={(event) => updateSaml({ nameIdFormat: event.target.value })} />
                  </Field>
                </>
              )}
            </div>
          )}

          <div className="border-t border-[color:var(--border)] pt-5 text-[13px] font-semibold text-[var(--text-primary)]">3. Who can sign in</div>
          <Field label="Email domains" htmlFor="sso-domains" error={errors.domains} hint="People with these email domains are sent to this connection from the sign-in page.">
            <input id="sso-domains" className={inputClass} value={domainsText} onChange={(event) => setDomainsText(event.target.value)} placeholder="example.com" spellCheck={false} />
          </Field>
          <Field label="Role for everyone who signs in" hint="Leave empty to grant nothing unless a group below matches.">
            <RolePicker roles={roleOptions} value={draft.defaultRoles} onChange={(defaultRoles) => update({ defaultRoles })} />
          </Field>
          <Field label="Group roles" error={errors.roleMappings} hint="Group names exactly as your provider sends them.">
            <div className="space-y-2">
              {draft.roleMappings.map((mapping, index) => (
                <div key={index} className="flex items-start gap-2">
                  <input
                    className={`${inputClass} font-mono`}
                    value={mapping.group}
                    placeholder="okta-security-admins"
                    aria-label={`Group ${index + 1}`}
                    onChange={(event) =>
                      update({ roleMappings: draft.roleMappings.map((item, i) => (i === index ? { ...item, group: event.target.value } : item)) })
                    }
                  />
                  <select
                    className={`${inputClass} max-w-[200px]`}
                    value={mapping.roles[0] ?? ""}
                    aria-label={`Role for group ${index + 1}`}
                    onChange={(event) =>
                      update({
                        roleMappings: draft.roleMappings.map((item, i) => (i === index ? { ...item, roles: event.target.value ? [event.target.value] : [] } : item)),
                      })
                    }
                  >
                    <option value="">Choose role</option>
                    {roleOptions.map((role) => (
                      <option key={role} value={role}>
                        {role}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="secondary-button inline-flex h-9 w-9 shrink-0 items-center justify-center p-0"
                    aria-label={`Remove group ${index + 1}`}
                    onClick={() => update({ roleMappings: draft.roleMappings.filter((_, i) => i !== index) })}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              <button
                type="button"
                className="secondary-button inline-flex h-8 items-center gap-1.5 px-3 text-[12px]"
                onClick={() => update({ roleMappings: [...draft.roleMappings, { group: "", roles: [] }] })}
              >
                <Plus className="h-3.5 w-3.5" /> Add group
              </button>
            </div>
          </Field>
          <Toggle
            label="Create accounts on first sign-in"
            description="Off means only people provisioned through SCIM can sign in."
            checked={draft.jitProvisioning}
            onChange={(jitProvisioning) => update({ jitProvisioning })}
          />

          {save.error && (
            <p className="rounded-md bg-red-50 px-3 py-2 text-[12px] text-red-800 dark:bg-red-500/10 dark:text-red-200" role="alert">
              {save.error.message}
            </p>
          )}
          <div className="flex justify-end gap-2 border-t border-[color:var(--border)] pt-4">
            <button type="button" onClick={onCancel} className="secondary-button inline-flex h-9 items-center px-3 text-[13px]">
              Cancel
            </button>
            <button type="button" onClick={submit} disabled={save.isPending} className="primary-button inline-flex h-9 items-center gap-2 px-4 text-[13px]">
              {save.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              {connection ? "Save changes" : "Save connection"}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

function RolePicker({ roles, value, onChange }: { roles: string[]; value: string[]; onChange: (value: string[]) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {roles.map((role) => {
        const selected = value.includes(role);
        return (
          <button
            key={role}
            type="button"
            aria-pressed={selected}
            onClick={() => onChange(selected ? value.filter((item) => item !== role) : [...value, role])}
            className={`rounded-md border px-2 py-1 font-mono text-[11px] transition ${
              selected
                ? "border-[color:var(--primary)] bg-[var(--primary)]/10 text-[var(--text-primary)]"
                : "border-[color:var(--border)] text-[var(--text-secondary)] hover:border-[color:var(--border-strong)]"
            }`}
          >
            {role}
          </button>
        );
      })}
    </div>
  );
}
