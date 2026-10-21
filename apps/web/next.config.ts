import type { NextConfig } from "next";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import packageJson from "./package.json";

const root = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(root, "../..");

const readGitValue = (args: string[]) => {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
};

const firstConfiguredVersion = () => {
  const envKeys = [
    "NEXT_PUBLIC_CEREBRO_WEB_VERSION",
    "NEXT_PUBLIC_APP_VERSION",
    "CEREBRO_WEB_VERSION",
    "APP_VERSION",
    "RELEASE_VERSION",
    "IMAGE_TAG",
    "GITHUB_REF_NAME",
    "VERCEL_GIT_COMMIT_REF",
  ];

  for (const key of envKeys) {
    const value = process.env[key]?.trim();
    if (value && value !== "main" && value !== "master") {
      return value;
    }
  }

  return "";
};

const resolveAppVersion = () => {
  const configuredVersion = firstConfiguredVersion();
  if (configuredVersion) {
    return configuredVersion;
  }

  const describedVersion = readGitValue(["describe", "--tags", "--dirty", "--always"]);
  if (describedVersion) {
    return describedVersion;
  }

  const sha =
    process.env.GITHUB_SHA?.trim() ||
    process.env.VERCEL_GIT_COMMIT_SHA?.trim() ||
    readGitValue(["rev-parse", "--short", "HEAD"]);

  if (sha) {
    return sha.slice(0, 12);
  }

  return packageJson.version;
};

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: workspaceRoot,
  // SAML XML signature handling and the AWS SDK are Node-only libraries; load them from node_modules at
  // runtime instead of bundling them into server chunks.
  serverExternalPackages: ["@node-saml/node-saml", "@aws-sdk/client-secrets-manager"],
  env: {
    NEXT_PUBLIC_CEREBRO_WEB_VERSION: resolveAppVersion(),
  },
  turbopack: {
    root: workspaceRoot,
  },
  // The console pages moved from /connectors to /integrations; API paths under
  // /api are unaffected because they never matched these sources.
  async redirects() {
    return [
      { source: "/connectors", destination: "/integrations", permanent: false },
      { source: "/connectors/:path*", destination: "/integrations/:path*", permanent: false },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        // Content-Security-Policy is set per request by src/proxy.ts so that
        // script-src can carry a nonce instead of 'unsafe-inline'.
        headers: [
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
};

export default nextConfig;
