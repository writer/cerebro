import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(here, "../src");

function dataModuleURL(source) {
  return `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
}

async function loadJiraModules() {
  const indexSource = stripTypeScriptTypes(await readFile(path.join(srcDir, "index.ts"), "utf8"));
  const indexURL = dataModuleURL(indexSource);
  const jiraSource = stripTypeScriptTypes(await readFile(path.join(srcDir, "jira.ts"), "utf8")).replace(
    '"./index.js"',
    JSON.stringify(indexURL),
  );
  const jiraURL = dataModuleURL(jiraSource);
  const jira = await import(jiraURL);
  const index = await import(indexURL);
  return {
    buildJiraWorkspaceClaims: jira.buildJiraWorkspaceClaims,
    Client: index.Client,
  };
}

test("buildJiraWorkspaceClaims rejects object-coerced identifiers", async () => {
  const { buildJiraWorkspaceClaims, Client } = await loadJiraModules();
  const client = new Client({ baseUrl: "https://cerebro.example.com" });
  const integration = client.integration({
    runtimeId: "writer-jira",
    tenantId: "writer",
    integration: "jira",
  });

  assert.throws(
    () =>
      buildJiraWorkspaceClaims(integration, {
        workspaceKey: { id: "writer" },
      }),
    /posture\.workspaceKey is required/,
  );

  assert.throws(
    () =>
      buildJiraWorkspaceClaims(integration, {
        workspaceKey: "writer",
        projects: [{ key: { id: "ENG" } }],
      }),
    /posture\.projects\[\]\.key is required/,
  );
});
