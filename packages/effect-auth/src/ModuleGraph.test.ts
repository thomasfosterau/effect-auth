import { describe, it, expect } from "vite-plus/test";
import { Array as Arr } from "effect";
import { access, readFile } from "node:fs/promises";
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

/** Whether `file` exists (any access failure reads as absent, as `existsSync`). */
const exists = (file: string): Promise<boolean> =>
  access(file).then(
    () => true,
    () => false,
  );

interface ModuleGraph {
  readonly files: ReadonlySet<string>;
  readonly externalSpecifiers: ReadonlySet<string>;
}

const walkModuleGraph = async (entry: string): Promise<ModuleGraph> => {
  const visited = new Set<string>();
  const externalSpecifiers = new Set<string>();
  const visit = async (file: string): Promise<void> => {
    if (visited.has(file)) return;
    visited.add(file);

    const source = await readFile(file, "utf8");
    await Arr.reduce(extractSpecifiers(source), Promise.resolve(), async (previous, specifier) => {
      await previous;
      if (!isRelativeSpecifier(specifier)) {
        externalSpecifiers.add(specifier);
        return;
      }
      const resolved = path.resolve(path.dirname(file), specifier);
      if (await exists(resolved)) await visit(resolved);
    });
  };
  await visit(entry);

  return { files: visited, externalSpecifiers };
};

const reachesModule = (externalSpecifiers: ReadonlySet<string>, moduleName: string): boolean =>
  [...externalSpecifiers].some(
    (specifier) => specifier === moduleName || specifier.startsWith(`${moduleName}/`),
  );

describe("module graph", () => {
  // TODO(#205): Http.ts — reached from src/index.ts's
  // `export * as Http from "./http/index.ts"` — imports from
  // `effect/http-api`, which is exactly the coupling #205's HTTP-tier
  // restructure exists to remove. Un-skip once that lands.
  it.skip("root barrel does not reach effect/http-api or effect-jsonapi", async () => {
    const { externalSpecifiers } = await walkModuleGraph(entryFile);

    expect(reachesModule(externalSpecifiers, "effect/http-api")).toBe(false);
    expect(reachesModule(externalSpecifiers, "effect-jsonapi")).toBe(false);
  });
});

describe("the ladder subpath", () => {
  // `@thomasfosterau/effect-auth/ladder` is imported by browser bundles for UX
  // gates, so it must not pull `effect` — or anything else — in with it.
  it("imports nothing at all", async () => {
    const ladder = path.resolve(import.meta.dirname, "Ladder.ts");
    // Comments stripped first: the module's JSDoc `@example` imports it by
    // its own subpath, which is documentation, not an edge.
    const code = (await readFile(ladder, "utf8"))
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    expect(extractSpecifiers(code)).toEqual([]);
  });
});

describe("the testing subpath", () => {
  const testingDir = path.resolve(import.meta.dirname, "testing");
  const testingEntry = path.join(testingDir, "index.ts");

  it("is not reachable from the root barrel", async () => {
    const { files } = await walkModuleGraph(entryFile);
    const reached = [...files].filter((file) => file.startsWith(`${testingDir}${path.sep}`));
    expect(reached).toEqual([]);
  });

  it("does not reach the HTTP tier", async () => {
    const { files, externalSpecifiers } = await walkModuleGraph(testingEntry);
    const httpDir = path.resolve(import.meta.dirname, "http");

    expect([...files].filter((file) => file.startsWith(`${httpDir}${path.sep}`))).toEqual([]);
    expect(reachesModule(externalSpecifiers, "effect/http-api")).toBe(false);
    expect(reachesModule(externalSpecifiers, "effect-jsonapi")).toBe(false);
  });

  it("does not import the test runner", async () => {
    const { externalSpecifiers } = await walkModuleGraph(testingEntry);
    expect(reachesModule(externalSpecifiers, "vite-plus")).toBe(false);
    expect(reachesModule(externalSpecifiers, "vitest")).toBe(false);
  });
});
