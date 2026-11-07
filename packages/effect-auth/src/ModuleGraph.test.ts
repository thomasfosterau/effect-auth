import { describe, it, expect } from "vite-plus/test";
import { Array as Arr, MutableHashSet } from "effect";
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
  readonly files: MutableHashSet.MutableHashSet<string>;
  readonly externalSpecifiers: MutableHashSet.MutableHashSet<string>;
}

const walkModuleGraph = async (entry: string): Promise<ModuleGraph> => {
  const visited = MutableHashSet.empty<string>();
  const externalSpecifiers = MutableHashSet.empty<string>();
  const visit = async (file: string): Promise<void> => {
    if (MutableHashSet.has(visited, file)) return;
    MutableHashSet.add(visited, file);

    const source = await readFile(file, "utf8");
    await Arr.reduce(extractSpecifiers(source), Promise.resolve(), async (previous, specifier) => {
      await previous;
      if (!isRelativeSpecifier(specifier)) {
        MutableHashSet.add(externalSpecifiers, specifier);
        return;
      }
      const resolved = path.resolve(path.dirname(file), specifier);
      if (await exists(resolved)) await visit(resolved);
    });
  };
  await visit(entry);

  return { files: visited, externalSpecifiers };
};

const reachesModule = (
  externalSpecifiers: MutableHashSet.MutableHashSet<string>,
  moduleName: string,
): boolean =>
  Arr.fromIterable(externalSpecifiers).some(
    (specifier) => specifier === moduleName || specifier.startsWith(`${moduleName}/`),
  );

describe("module graph", () => {
  // The HTTP tier is reachable only through the `./http` subpath (#205), so
  // the headless core costs a consumer no `effect/http-api` and no JSON:API.
  it("root barrel does not reach effect/http-api or effect-jsonapi", async () => {
    const { externalSpecifiers } = await walkModuleGraph(entryFile);

    expect(reachesModule(externalSpecifiers, "effect/http-api")).toBe(false);
    expect(reachesModule(externalSpecifiers, "effect-jsonapi")).toBe(false);
  });

  // `./client`, `./sql` and `./saml` are subpaths a consumer opts into; the
  // root barrel loads none of them, and in particular never the HTTP tier
  // (which `./client` reaches for its wire types).
  it("reaches neither the HTTP tier nor the client, SQL or SAML subpaths", async () => {
    const { files } = await walkModuleGraph(entryFile);
    const reached = (dir: string) => {
      const root = path.resolve(import.meta.dirname, dir);
      return [...files].filter((file) => file.startsWith(`${root}${path.sep}`));
    };

    expect(reached("http")).toEqual([]);
    expect(reached("client")).toEqual([]);
    expect(reached("sql")).toEqual([]);
    expect(reached("saml")).toEqual([]);
  });

  // `@node-saml/node-saml` is an optional peer that only `./saml` imports: a
  // consumer of the root never needs it installed, and the root stays
  // runnable outside Node.
  it("root barrel does not reach @node-saml/node-saml", async () => {
    const { externalSpecifiers } = await walkModuleGraph(entryFile);

    expect(reachesModule(externalSpecifiers, "@node-saml/node-saml")).toBe(false);
    expect(reachesModule(externalSpecifiers, "xml-crypto")).toBe(false);
  });
});

describe("the saml subpath", () => {
  it("is the only entry that reaches @node-saml/node-saml", async () => {
    const { externalSpecifiers } = await walkModuleGraph(
      path.resolve(import.meta.dirname, "saml", "index.ts"),
    );
    expect(reachesModule(externalSpecifiers, "@node-saml/node-saml")).toBe(true);
  });
});

describe("the client subpath", () => {
  // The browser bundle holds only the client: its `http/` imports are type-only
  // and erase, so its runtime graph is the client module alone.
  it("imports the HTTP tier for types only", async () => {
    const client = path.resolve(import.meta.dirname, "client", "Client.ts");
    const code = (await readFile(client, "utf8"))
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    const valueImports = [
      ...code.matchAll(/^import\s+(?!type\b)[^;]*?from\s+["']([^"']+)["']/gm),
    ].map((match) => match[1]);
    expect(valueImports).toEqual([]);
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
