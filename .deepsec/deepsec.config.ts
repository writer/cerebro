import { defineConfig } from "deepsec/config";

export default defineConfig({
  projects: [
    {
      id: "cerebro",
      root: "..",
      githubUrl: "https://github.com/writer/cerebro/blob/main",
      priorityPaths: [
        "internal/api/",
        "internal/auth/",
        "internal/apiauth/",
        "internal/agents/",
        "internal/remediation/",
        "internal/actionengine/",
        "internal/providers/",
        "internal/cli/",
      ],
    },
    // <deepsec:projects-insert-above>
  ],
});
