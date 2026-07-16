import type {
  AdmissionContext,
  AdmissionPolicy,
  AdmissionStatus,
  InstallationLifecycleState,
} from "./contracts.js";

const installationTransitions: Readonly<
  Record<InstallationLifecycleState, readonly InstallationLifecycleState[]>
> = {
  authorizing: ["binding"],
  binding: ["verifying"],
  verifying: ["active"],
  active: ["suspended", "revoked", "retired"],
  suspended: ["verifying", "retired"],
  revoked: ["verifying", "retired"],
  retired: [],
};

export function isInstallationTransitionAllowed(
  from: InstallationLifecycleState,
  to: InstallationLifecycleState,
): boolean {
  return installationTransitions[from].includes(to);
}

export function admissionStatus(
  context: AdmissionContext,
  policy: AdmissionPolicy,
): AdmissionStatus {
  const serviceState = context.presence.service_state;

  if (context.binding.state !== "active") {
    return {
      admit: false,
      message: installationMessage(context.binding.state),
      retryable: context.binding.state !== "retired",
      service_state: serviceState,
    };
  }

  if (
    context.presence.compatibility === "blocked" ||
    context.presence.compatibility === "incompatible"
  ) {
    return {
      admit: false,
      message: "This request needs a capability that is not available.",
      retryable: context.presence.compatibility === "blocked",
      service_state: serviceState,
    };
  }

  switch (serviceState) {
    case "ready":
      return {
        accepted_status: "queued",
        admit: true,
        message: "Request queued.",
        retryable: false,
        service_state: serviceState,
      };
    case "degraded":
      if (!policy.admit_while_degraded) {
        return {
          admit: false,
          message: "The agent is temporarily degraded. Retry this request.",
          retryable: true,
          service_state: serviceState,
        };
      }
      return {
        accepted_status: "degraded",
        admit: true,
        message: "Request queued. Some capabilities are temporarily unavailable.",
        retryable: false,
        service_state: serviceState,
      };
    case "recovering":
      return {
        accepted_status: "recovering",
        admit: true,
        message: "Request queued. Processing will resume during recovery.",
        retryable: false,
        service_state: serviceState,
      };
    case "offline":
      if (policy.offline_behavior === "queue") {
        return {
          accepted_status: "recovering",
          admit: true,
          message: "Request queued. Processing will resume when the agent is online.",
          retryable: false,
          service_state: serviceState,
        };
      }
      return {
        admit: false,
        message: "The agent is offline. Retry this request later.",
        retryable: true,
        service_state: serviceState,
      };
    case "booting":
    case "warming":
    case "draining":
      return {
        admit: false,
        message: "No admission edge is ready. Retry this request.",
        retryable: true,
        service_state: serviceState,
      };
    case "stopped":
      return {
        admit: false,
        message: "This agent service is stopped.",
        retryable: false,
        service_state: serviceState,
      };
  }
}

function installationMessage(state: InstallationLifecycleState): string {
  switch (state) {
    case "authorizing":
    case "binding":
    case "verifying":
      return "The Slack installation is not ready yet.";
    case "suspended":
      return "The Slack installation is suspended.";
    case "revoked":
      return "Slack authorization must be restored.";
    case "retired":
      return "This Slack installation is retired.";
    case "active":
      return "The Slack installation is active.";
  }
}
