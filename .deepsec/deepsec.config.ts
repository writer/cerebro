import { defineConfig } from "deepsec/config";

export default defineConfig({
  projects: [
    {
      id: "cerebro",
      root: "..",
      githubUrl: "https://github.com/writer/cerebro/blob/main",
      priorityPaths: [
        "cmd/cerebro/",
        "internal/bootstrap/",
        "internal/config/",
        "internal/findings/",
        "internal/graphingest/",
        "internal/graphquery/",
        "internal/sourceprojection/",
        "internal/sourceruntime/",
      ],
    },
    // <deepsec:projects-insert-above>
  ],
});
