import type { CanonicalWorkItemPort } from "@writer/cerebro-slack-companion";
import type { ComplianceWorkCommand } from "@writer/cerebro-sdk";
import type {
  CanonicalHostBinding,
  CanonicalWorkTransport,
  CanonicalWorkTransportFactory,
} from "./types.js";

export class PrivateCanonicalWorkItemAdapter implements CanonicalWorkItemPort {
  private readonly binding: CanonicalHostBinding;
  private readonly transports: CanonicalWorkTransportFactory;

  constructor(binding: CanonicalHostBinding, transports: CanonicalWorkTransportFactory) {
    this.binding = validateBinding(binding);
    this.transports = transports;
  }

  async command(
    workItemId: string,
    command: ComplianceWorkCommand,
    context: { idempotency_key: string },
  ) {
    const idempotencyKey = requiredRef(context.idempotency_key, "idempotency_key");
    return (await this.transport()).command(workItemId, command, {
      idempotency_key: idempotencyKey,
      tenant_ref: this.binding.tenant_ref,
    });
  }

  async get(workItemId: string) {
    return (await this.transport()).get(workItemId, { tenant_ref: this.binding.tenant_ref });
  }

  async list(options: Parameters<CanonicalWorkItemPort["list"]>[0] = {}) {
    return (await this.transport()).list({ ...options, tenant_ref: this.binding.tenant_ref });
  }

  private transport(): Promise<CanonicalWorkTransport> {
    return this.transports.bind({
      credential_ref: this.binding.credential_ref,
      integration_ref: this.binding.integration_ref,
    });
  }
}

function validateBinding(binding: CanonicalHostBinding): CanonicalHostBinding {
  return {
    credential_ref: requiredOpaqueRef(binding.credential_ref, "credential_ref"),
    integration_ref: requiredOpaqueRef(binding.integration_ref, "integration_ref"),
    tenant_ref: requiredOpaqueRef(binding.tenant_ref, "tenant_ref"),
  };
}

function requiredOpaqueRef(value: string, field: string): string {
  const normalized = requiredRef(value, field);
  if (!/^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~:/-]+$/.test(normalized)) {
    throw new Error(`${field} must be an opaque host reference`);
  }
  if (normalized.startsWith("http://") || normalized.startsWith("https://")) {
    throw new Error(`${field} must not be an endpoint URL`);
  }
  return normalized;
}

function requiredRef(value: string, field: string): string {
  const normalized = value?.trim();
  if (!normalized || normalized.length > 2_048) throw new Error(`${field} is required`);
  return normalized;
}
