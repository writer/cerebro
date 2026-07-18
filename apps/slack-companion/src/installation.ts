import type {
  InstallationTransition,
  InstallationTransitionResult,
} from "./contracts.js";
import { isInstallationTransitionAllowed } from "./lifecycle.js";
import type { InstallationLifecyclePort } from "./ports.js";

export class InstallationLifecycleController {
  constructor(private readonly store: InstallationLifecyclePort) {}

  async transition(
    transition: InstallationTransition,
  ): Promise<InstallationTransitionResult> {
    if (!isInstallationTransitionAllowed(transition.from, transition.to)) {
      throw new Error(
        `installation transition ${transition.from} -> ${transition.to} is not allowed`,
      );
    }
    if (transition.reason_code.trim() === "") {
      throw new Error("reason_code is required");
    }
    return this.store.compareAndSet(transition);
  }
}
