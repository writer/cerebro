import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

import { describe, expect, it } from "vitest";

const projectPath = (...parts: string[]) => join(process.cwd(), ...parts);
const appRoot = projectPath("src", "app");
const sourceRoot = projectPath("src");

const walk = (directory: string): string[] =>
  readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = join(directory, entry.name);
    return entry.isDirectory() ? walk(fullPath) : [fullPath];
  });

const routeOf = (pageFile: string) => {
  const route = `/${relative(appRoot, pageFile).replace(/\/page\.tsx$/, "")}`;
  return route === "/page.tsx" ? "/" : route;
};

const definedRoutes = () =>
  walk(appRoot)
    .filter((file) => file.endsWith(`${"/"}page.tsx`))
    .map(routeOf);

// A dynamic segment accepts any single path segment, so [id] has to match a concrete link.
const routeMatcher = (route: string) => new RegExp(`^${route.replace(/\[[^\]]+\]/g, "[^/]+")}$`);

const linkPatterns = [
  /href=["`](\/[^"`${}]*)["`]/g,
  /href:\s*["`](\/[^"`${}]*)["`]/g,
  /\.push\(["`](\/[^"`${}]*)["`]/g,
  /iconHref:\s*["`](\/[^"`${}]*)["`]/g,
];

describe("internal link targets", () => {
  it("points every internal link at a route that exists", () => {
    const routes = definedRoutes();
    const matchers = routes.map(routeMatcher);
    const resolves = (path: string) => routes.includes(path) || matchers.some((rx) => rx.test(path));

    const dead = walk(sourceRoot)
      .filter((file) => /\.tsx?$/.test(file) && !file.includes(".test."))
      .flatMap((file) => {
        const source = readFileSync(file, "utf8");
        return linkPatterns.flatMap((pattern) =>
          [...source.matchAll(pattern)]
            .map((match) => match[1].split("?")[0].split("#")[0])
            .filter((path) => path !== "/" && !path.startsWith("/api/"))
            .filter((path) => !resolves(path))
            .map((path) => `${relative(sourceRoot, file)} -> ${path}`),
        );
      });

    expect(dead).toEqual([]);
  });

  it("keeps route segments free of hyphens", () => {
    const hyphenated = definedRoutes().filter((route) =>
      route
        .split("/")
        .filter((segment) => !segment.startsWith("["))
        .some((segment) => segment.includes("-")),
    );

    expect(hyphenated).toEqual([]);
  });
});
