import { describe, it, expect } from "vite-plus/test";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Static import-graph walker
//
// Resolves imports by reading and regex-parsing source text — it never
// executes the barrel, so the graph reflects what's on disk rather than
// whatever a particular runtime happens to load.
// ---------------------------------------------------------------------------

const repoRoot = path.resolve(import.meta.dirname, "../../..");
const entryFile = path.resolve(import.meta.dirname, "index.ts");

// Captures the string literal following `from`, a bare side-effect
// `import "..."`, or a dynamic `import("...")`.
const SPECIFIER_PATTERN = /(?:from|import)\s*\(?\s*["']([^"']+)["']/g;

const isRelativeSpecifier = (specifier: string): boolean =>
  specifier.startsWith(".") || specifier.startsWith("/");

const extractSpecifiers = (source: string): string[] =>
  [...source.matchAll(SPECIFIER_PATTERN)].map((match) => match[1]);

interface ModuleGraph {
  readonly externalSpecifiers: ReadonlySet<string>;
}

const walkModuleGraph = (entry: string): ModuleGraph => {
  const visited = new Set<string>();
  const externalSpecifiers = new Set<string>();
  const queue = [entry];

  while (queue.length > 0) {
    const file = queue.pop()!;
    if (visited.has(file)) continue;
    visited.add(file);

    const source = fs.readFileSync(file, "utf8");
    for (const specifier of extractSpecifiers(source)) {
      if (!isRelativeSpecifier(specifier)) {
        externalSpecifiers.add(specifier);
        continue;
      }
      const resolved = path.resolve(path.dirname(file), specifier);
      if (fs.existsSync(resolved) && !visited.has(resolved)) {
        queue.push(resolved);
      }
    }
  }

  return { externalSpecifiers };
};

const reachesModule = (externalSpecifiers: ReadonlySet<string>, moduleName: string): boolean =>
  [...externalSpecifiers].some(
    (specifier) => specifier === moduleName || specifier.startsWith(`${moduleName}/`),
  );

describe("module graph", () => {
  it("has no reference to legation anywhere in the repo", () => {
    // This file's own source necessarily names the term it's checking for
    // (in this test's description and in the `.includes(...)` call below),
    // so it's excluded from the scan rather than flagging itself.
    const selfPath = path.relative(repoRoot, import.meta.filename);

    const trackedFiles = execFileSync("git", ["ls-files"], {
      cwd: repoRoot,
      encoding: "utf8",
    })
      .split("\n")
      .filter((line) => line.length > 0 && line !== selfPath);

    const offenders = trackedFiles.filter((relativePath) =>
      fs.readFileSync(path.join(repoRoot, relativePath), "utf8").toLowerCase().includes("legation"),
    );

    expect(offenders).toEqual([]);
  });

  // TODO(#205): Http.ts — reached from src/index.ts:390's
  // `export * as Http from "./http/index.ts"` — imports from
  // `effect/unstable/httpapi`, which is exactly the coupling #205's HTTP-tier
  // restructure exists to remove. Un-skip once that lands.
  it.skip("root barrel does not reach effect/unstable/httpapi or effect-jsonapi", () => {
    const { externalSpecifiers } = walkModuleGraph(entryFile);

    expect(reachesModule(externalSpecifiers, "effect/unstable/httpapi")).toBe(false);
    expect(reachesModule(externalSpecifiers, "effect-jsonapi")).toBe(false);
  });
});
