import { describe, expect, it } from "vite-plus/test";
import * as Arr from "effect/Array";
import { readdir, readFile } from "node:fs/promises";
import * as path from "node:path";

const SPECIFIER_PATTERN = /(?:from|import)\s*\(?\s*["']([^"']+)["']/g;

/** Every import specifier of each library source (not the suites or the fake). */
const librarySpecifiers = async (): Promise<ReadonlyArray<readonly [string, string]>> => {
  const files = (await readdir(import.meta.dirname)).filter(
    (file) => file.endsWith(".ts") && !file.endsWith(".test.ts") && !file.endsWith(".fixtures.ts"),
  );
  const sources = await Promise.all(
    files.map((file) => readFile(path.join(import.meta.dirname, file), "utf8")),
  );
  return Arr.flatMap(Arr.zip(files, sources), ([file, source]) =>
    [...source.matchAll(SPECIFIER_PATTERN)].map((match) => [file, match[1] ?? ""] as const),
  );
};

describe("module graph", () => {
  it("imports no Node built-in, so it runs on Workers", async () => {
    const specifiers = await librarySpecifiers();
    expect(specifiers.length).toBeGreaterThan(0);
    expect(specifiers.filter(([, spec]) => spec.startsWith("node:"))).toEqual([]);
  });

  it("reaches the core only through its root", async () => {
    const core = (await librarySpecifiers()).filter(([, spec]) =>
      spec.startsWith("@thomasfosterau/effect-auth"),
    );
    expect(core.filter(([, spec]) => spec !== "@thomasfosterau/effect-auth")).toEqual([]);
  });
});
