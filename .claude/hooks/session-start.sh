#!/usr/bin/env bash
#
# Provision a checkout for NON-INTERACTIVE use.
#
# One file, two callers — the Claude Code SessionStart hook and the
# devcontainer's `postCreateCommand` (which invokes this file directly) — so a
# container shell and an agent session are provisioned identically. Shape
# copied from effect-jsonapi / effect-drizzle-ext (the library reference); the
# `website#NNN` citations name the issues in that application's tracker that
# are the evidence behind a decision, not tickets in this one.
#
# ## The problem it solves
#
# A Claude Code session (local or on the web) runs every tool call in a
# non-interactive shell. The toolchain a human gets from `~/.bashrc` (or from
# corepack in the devcontainer) is not on that shell's PATH, and the repo's own
# binaries — `vp`, `fallow` (which the PreToolUse fallow gate runs before
# every agent `git commit` / `git push`) and `tsx` — live in
# `node_modules`, which is on nobody's PATH. Rather than fight PATH — which this script cannot export into its
# caller — it links the tools into `~/.local/bin`, which is on PATH in the
# devcontainer image and the web sandbox alike. A symlink survives where an
# `export` cannot.
#
# ## What it does
#
# 1. Enables corepack when pnpm is missing, so the pinned `packageManager`
#    version resolves.
# 2. Installs dependencies against the lockfile — unconditionally, because a
#    prebaked container can carry a tree built from an OLDER lockfile, and
#    stale dependencies masquerade as trunk breakage. `--frozen-lockfile` is a
#    fast no-op when in sync.
# 3. Writes `vp`, `fallow` and `tsx` re-exec shims into ~/.local/bin.
#
# After it, `vp check`, `vp run check` and `vp run -r test:unit` run with no
# manual setup.
#
# ## Secrets
#
# This hook hydrates NO secrets, and this repository needs none: no gate needs
# a credential. `vp run check:dist` and `pnpm audit` need registry access; the
# rest run offline against the lockfile. Publishing is the release workflow's job
# and uses npm OIDC trusted publishing (PUBLISHING.md), so there is no token to
# hydrate anywhere.
#
# ## Contract
#
# Idempotent, and never fatal. Every failure path logs and continues, because
# the SessionStart hook must not block a session and a half-provisioned
# container is more useful than one that refused to start.
#
# Untrusted-content note: this script reads only fixed, hardcoded paths. It
# takes no input from repo content, issue or PR bodies, or anything an agent
# could have been persuaded to write earlier in a session. Do not add such
# input without revisiting this note — it runs on every session start and
# container create.

set -uo pipefail

log() { printf '[session-start] %s\n' "$1" >&2; }

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
LOCAL_BIN="${HOME:-/root}/.local/bin"

mkdir -p "$LOCAL_BIN" 2>/dev/null || log "cannot create $LOCAL_BIN; continuing"

# Each tool gets a re-exec shim rather than a plain symlink, for two reasons.
# pnpm's `node_modules/.bin/*` entries are shell scripts that locate their
# package relative to their own path (`$0`), so a symlink to one in
# ~/.local/bin resolves `~/.local/<pkg>` and dies with "Cannot find module".
# And a symlink always resolves to $PROJECT_DIR's node_modules, even when
# invoked with cwd inside a git worktree, so `vp` would load the primary
# tree's vitest while the worktree's test modules resolve the worktree's own
# copy; two physical instances of the same vitest corrupt its module-level
# suite-collector state, and every describe() in the worktree throws `Cannot
# read properties of undefined (reading 'config')` (website#1663). Each shim
# walks up from $PWD for the nearest project-local copy and re-execs that,
# falling back to the primary checkout's when none is found. The marker keeps
# its original text (the issue is website#1663): shims written by earlier runs
# are recognised, and so replaced, by an exact match on it.
SHIM_MARKER="# generated-by: .claude/hooks/session-start.sh (vp re-exec shim, gardeneria issue #1663)"
# write_shim <name> <path of the tool relative to a project root>
write_shim() {
  name="$1"
  rel="$2"
  dest="$LOCAL_BIN/$name"
  # Leave a real, non-generated file alone (a globally installed tool). A
  # symlink (stale, or the broken kind this script once wrote) or a shim
  # generated earlier is fair game: the embedded fallback path can change
  # across containers.
  if [ -e "$dest" ] && [ ! -L "$dest" ] && ! grep -qF "$SHIM_MARKER" "$dest" 2>/dev/null; then
    return 0
  fi
  rm -f "$dest" 2>/dev/null
  cat >"$dest.tmp" <<SHIM
#!/usr/bin/env bash
$SHIM_MARKER
dir="\$PWD"
while [ -n "\$dir" ]; do
  if [ -x "\$dir/$rel" ]; then
    exec "\$dir/$rel" "\$@"
  fi
  [ "\$dir" = "/" ] && break
  dir="\$(dirname "\$dir")"
done
exec "$PROJECT_DIR/$rel" "\$@"
SHIM
  chmod +x "$dest.tmp" 2>/dev/null && mv -f "$dest.tmp" "$dest" 2>/dev/null \
    || { rm -f "$dest.tmp" 2>/dev/null; log "could not write $name shim"; }
}

# ── 1. pnpm ─────────────────────────────────────────────────────────────────
if ! command -v pnpm >/dev/null 2>&1; then
  log "pnpm not found; enabling corepack…"
  (corepack enable >/dev/null 2>&1 && cd "$PROJECT_DIR" && corepack install >/dev/null 2>&1) \
    || log "corepack could not provide pnpm; continuing"
fi

# ── 2. Dependencies ─────────────────────────────────────────────────────────
if [ -f "$PROJECT_DIR/pnpm-lock.yaml" ]; then
  log "syncing dependencies against the lockfile…"
  (cd "$PROJECT_DIR" && pnpm install --frozen-lockfile >/dev/null 2>&1) \
    || log "dependency install failed; continuing"
fi

# ── 3. Repo binaries on PATH ────────────────────────────────────────────────
write_shim vp node_modules/vite-plus/bin/vp
write_shim fallow node_modules/.bin/fallow
write_shim tsx node_modules/.bin/tsx

exit 0
