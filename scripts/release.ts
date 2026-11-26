/**
 * The Release workflow's scripts (docs/PUBLISHING.md), on Node built-ins only.
 * `pack [<out>]`, after `vp run build`, packs every unpublished public package
 * into `release/` with a manifest; `tag <sha> [<out>]` tags and releases each
 * manifest entry, skipping those already released.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

interface Entry {
  readonly name: string;
  readonly version: string;
  readonly dir: string;
  readonly tarball: string;
}

interface Manifest {
  readonly name: string;
  readonly version: string;
  readonly private?: boolean | undefined;
  readonly dependencies?: Record<string, string> | undefined;
  readonly peerDependencies?: Record<string, string> | undefined;
  readonly optionalDependencies?: Record<string, string> | undefined;
}

const root = resolve(import.meta.dirname, "..");

const readManifest = (dir: string): Manifest =>
  // SAFETY: a workspace package's own `package.json` always has `name` and
  // `version`; every other field `Manifest` reads is optional.
  JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8")) as Manifest;

const isPublished = async (name: string, version: string): Promise<boolean> => {
  const url = `https://registry.npmjs.org/${name.replace("/", "%2F")}/${version}`;
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (response.status === 404) return false;
  if (response.ok) return true;
  throw new Error(`${url}: HTTP ${response.status}`);
};

/** Workspace packages, each after the workspace packages it depends on. */
const workspacePackages = (): ReadonlyArray<{ dir: string; manifest: Manifest }> => {
  const all = readdirSync(join(root, "packages"))
    .map((name) => join("packages", name))
    .filter((dir) => existsSync(join(root, dir, "package.json")))
    .map((dir) => ({ dir, manifest: readManifest(dir) }));
  const byName = new Map(all.map((pkg) => [pkg.manifest.name, pkg]));
  const ordered: Array<(typeof all)[number]> = [];
  const visiting = new Set<string>();
  const visit = (pkg: (typeof all)[number]): void => {
    if (ordered.includes(pkg)) return;
    if (visiting.has(pkg.manifest.name)) throw new Error(`cycle at ${pkg.manifest.name}`);
    visiting.add(pkg.manifest.name);
    const { dependencies, peerDependencies, optionalDependencies } = pkg.manifest;
    for (const dep of Object.keys({
      ...dependencies,
      ...peerDependencies,
      ...optionalDependencies,
    })) {
      const internal = byName.get(dep);
      if (internal !== undefined) visit(internal);
    }
    visiting.delete(pkg.manifest.name);
    ordered.push(pkg);
  };
  all.forEach(visit);
  return ordered;
};

const pack = async (out: string): Promise<void> => {
  mkdirSync(out, { recursive: true });
  const candidates = workspacePackages().filter(({ manifest }) => manifest.private !== true);
  const published = await Promise.all(
    candidates.map(({ manifest }) => isPublished(manifest.name, manifest.version)),
  );
  const entries: Array<Entry> = [];
  for (const [i, { dir, manifest }] of candidates.entries()) {
    if (published[i]) continue;
    // SAFETY: `pnpm pack --json` prints one object whose `filename` is the
    // tarball's absolute path.
    // pnpm rewrites `catalog:` and `workspace:` specifiers as it packs.
    const packed = JSON.parse(
      execFileSync("vp", ["pm", "pack", "--pack-destination", out, "--json"], {
        cwd: join(root, dir),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "inherit"],
      }),
    ) as { readonly filename: string };
    const tarball = packed.filename.slice(packed.filename.lastIndexOf("/") + 1);
    entries.push({ name: manifest.name, version: manifest.version, dir, tarball });
    console.log(`packed ${manifest.name}@${manifest.version}`);
  }
  writeFileSync(join(out, "manifest.json"), `${JSON.stringify(entries, null, 2)}\n`);
  if (entries.length === 0) console.log("nothing to publish");
};

/** The body of `## <version>` in a Changesets CHANGELOG. */
const changelogSection = (dir: string, version: string): string => {
  const path = join(root, dir, "CHANGELOG.md");
  if (!existsSync(path)) return "";
  const lines = readFileSync(path, "utf8").split("\n");
  const start = lines.findIndex((line) => line.trim() === `## ${version}`);
  if (start === -1) return "";
  const end = lines.findIndex((line, i) => i > start && line.startsWith("## "));
  return lines
    .slice(start + 1, end === -1 ? undefined : end)
    .join("\n")
    .trim();
};

const gh = (args: ReadonlyArray<string>, input?: string): void => {
  execFileSync("gh", args, { input, stdio: ["pipe", "inherit", "inherit"] });
};

const released = (tag: string): boolean => {
  try {
    execFileSync("gh", ["release", "view", tag], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};

const tag = (sha: string, out: string): void => {
  // SAFETY: `pack` wrote this file from `Entry` values, and the artifact
  // carries it unchanged between jobs of one run.
  const entries = JSON.parse(
    readFileSync(join(out, "manifest.json"), "utf8"),
  ) as ReadonlyArray<Entry>;
  for (const entry of entries) {
    const name = `${entry.name}@${entry.version}`;
    if (released(name)) {
      console.log(`already released ${name}`);
      continue;
    }
    // `gh release create` creates the tag on `--target` when it is missing.
    gh(
      ["release", "create", name, "--target", sha, "--title", name, "--notes-file", "-"],
      changelogSection(entry.dir, entry.version),
    );
    console.log(`released ${name}`);
  }
};

const defaultOut = join(root, "release");
const [command, ...args] = process.argv.slice(2);
if (command === "pack") await pack(resolve(args[0] ?? defaultOut));
else if (command === "tag" && args[0] !== undefined && args[0] !== "")
  tag(args[0], resolve(args[1] ?? defaultOut));
else throw new Error("usage: node scripts/release.ts pack [<out>] | tag <sha> [<out>]");
