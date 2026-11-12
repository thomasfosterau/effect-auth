/**
 * The browser client names only routes the contract serves (#205): every
 * request it builds from a literal path is an operation of the OpenAPI
 * document, with the same method. A client left pointing at a removed route
 * (`/organization/…`, `/multi-session/…`, `GET /token`, …) fails here.
 */
import { readFile } from "node:fs/promises";
import * as R from "effect/Record";
import { describe, expect, it } from "vite-plus/test";
import { getOpenApiSpec } from "../http/HttpApi.ts";

/** The OpenAPI operation keys the contract uses. */
const METHODS = ["get", "post", "put", "patch", "delete"] as const;

/** One request the client source builds: its method and its path, `*` for a computed segment. */
interface ClientRoute {
  readonly method: string;
  readonly path: string;
}

/**
 * `jsonApi(…)` / `request(…)` calls with a literal method and a literal or
 * template path, read from the source with comments (and their examples) left out.
 */
const CALL =
  /\b(?:jsonApi|request)\b[^(;]*?\(\s*"(GET|POST|PUT|PATCH|DELETE)",\s*(?:"([^"]+)"|`([^`]+)`)/g;

const clientRoutes = (source: string): ReadonlyArray<ClientRoute> => {
  const code = source
    .split("\n")
    .filter((line) => !/^\s*(?:\*|\/\/|\/\*)/.test(line))
    .join("\n");
  return [...code.matchAll(CALL)].map(([, method = "", literal, template]) => ({
    method,
    path: (literal ?? template ?? "").split("?")[0]?.replaceAll(/\$\{[^}]+\}/g, "*") ?? "",
  }));
};

/** Whether `route`'s path matches the OpenAPI path template `template`. */
const matches = (template: string, path: string): boolean => {
  // A path built on a computed prefix (`${path}/members`) matches on its tail.
  const actual = path.split("/");
  const expected = template.split("/").slice(path.startsWith("*/") ? -actual.length : 0);
  return (
    expected.length === actual.length &&
    expected.every(
      (segment, i) => segment.startsWith("{") || actual[i] === "*" || actual[i] === segment,
    )
  );
};

describe("the client's routes", () => {
  it("are every one an operation of the contract, method included", async () => {
    const source = await readFile(new URL("./Client.ts", import.meta.url), "utf8");
    const routes = clientRoutes(source);
    // The scan sees the client's calls, not a handful of them.
    expect(routes.length).toBeGreaterThan(60);

    // Every `METHOD path` the contract serves, its path as an OpenAPI template.
    const served = R.toEntries(getOpenApiSpec().paths).flatMap(([template, item]) =>
      METHODS.filter((method) => item[method] !== undefined).map((method) => ({
        method: method.toUpperCase(),
        template,
      })),
    );
    const unknown = routes.filter(
      ({ method, path }) =>
        !served.some(
          (operation) => operation.method === method && matches(operation.template, path),
        ),
    );
    expect(unknown).toEqual([]);
  });
});
