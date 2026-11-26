import { readFile } from "node:fs/promises";
import path from "node:path";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Arr from "effect/Array";
import * as R from "effect/Record";
import { describe, expect, it } from "vite-plus/test";

const read = (file: string) => readFile(path.resolve(import.meta.dirname, file), "utf8");

// Subpaths that gate an optional peer or a runtime, or hold test support, and
// so stay lowercase with no root namespace.
const LOWERCASE = [
  "./http",
  "./client",
  "./client/atoms",
  "./client/testing",
  "./sql",
  "./scrypt",
  "./saml",
  "./testing",
];

const Manifest = Schema.fromJsonString(
  Schema.Struct({
    exports: Schema.Record(Schema.String, Schema.Struct({ import: Schema.String })),
  }),
);

describe("the export layout", () => {
  it("re-exports only namespaces from the root, each on its own subpath", async () => {
    const index = await read("index.ts");
    const manifest = Schema.decodeUnknownSync(Manifest)(await read("../package.json"));
    const statements = index.match(/^export .*$/gm) ?? [];
    const namespaces = [...index.matchAll(/^export \* as (\w+) from "\.\/([\w/]+)\.ts";$/gm)];
    expect(namespaces.length).toBe(statements.length);
    const expected = R.fromEntries(
      Arr.map(namespaces, ([, name, file]) => [`./${name}`, `./dist/${file}.js`] as const),
    );
    const actual = R.fromEntries(
      Arr.filterMap(R.toEntries(manifest.exports), ([key, entry]) =>
        key === "." || Arr.contains(LOWERCASE, key)
          ? Result.failVoid
          : Result.succeed([key, entry.import] as const),
      ),
    );
    expect(actual).toEqual(expected);
  });
});
