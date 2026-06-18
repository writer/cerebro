import { defineConfig } from "deepsec/config";

export default defineConfig({
  projects: [
    {
      id: "cerebro",
      root: "..",
      githubUrl: "https://github.com/writer/cerebro/blob/main",
      priorityPaths: [
        ".github/workflows/",
        "api/",
        "cmd/cerebro/",
        "internal/bootstrap/",
        "internal/config/",
        "internal/connectorcatalog/",
        "internal/deviceauth/",
        "internal/findings/",
        "internal/graphagent/",
        "internal/graphingest/",
        "internal/graphquery/",
        "internal/sourcehttp/",
        "internal/sourceprojection/",
        "internal/sourceruntime/",
        "policies/",
        "sources/",
        "tools/",
      ],
    },
    // <deepsec:projects-insert-above>
  ],
});
