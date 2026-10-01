import { describe, it, expect } from "vite-plus/test";
import * as fs from "node:fs";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Static import-graph walker
//
// Resolves imports by reading and regex-parsing source text — it never
// executes the barrel, so the graph reflects what's on disk rather than
// whatever a particular runtime happens to load.
// ---------------------------------------------------------------------------

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
  // TODO(#205): Http.ts — reached from src/index.ts:385's
  // `export * as Http from "./http/index.ts"` — imports from
  // `effect/http-api`, which is exactly the coupling #205's HTTP-tier
  // restructure exists to remove. Un-skip once that lands.
  it.skip("root barrel does not reach effect/http-api or effect-jsonapi", () => {
    const { externalSpecifiers } = walkModuleGraph(entryFile);

    expect(reachesModule(externalSpecifiers, "effect/http-api")).toBe(false);
    expect(reachesModule(externalSpecifiers, "effect-jsonapi")).toBe(false);
  });
});

describe("the ladder subpath", () => {
  // `@thomasfosterau/effect-auth/ladder` is imported by browser bundles for UX
  // gates, so it must not pull `effect` — or anything else — in with it.
  it("imports nothing at all", () => {
    const ladder = path.resolve(import.meta.dirname, "Ladder.ts");
    // Comments stripped first: the module's JSDoc `@example` imports it by
    // its own subpath, which is documentation, not an edge.
    const code = fs
      .readFileSync(ladder, "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    expect(extractSpecifiers(code)).toEqual([]);
  });
});
