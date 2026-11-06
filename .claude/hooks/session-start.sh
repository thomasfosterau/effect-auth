#!/usr/bin/env bash
#
# Provision a checkout for NON-INTERACTIVE use.
#
# One file, two callers — the Claude Code SessionStart hook and the
# devcontainer's `postCreateCommand` (which invokes this file directly) — so a
# container shell and an agent session are provisioned identically. Shape
# copied from effect-ext (the library reference, effect-ext#47); the
# `website#NNN` citations name the issues in that application's tracker that
# are the evidence behind a decision, not tickets in this one.
#
# ## Vite+ first
#
# A Claude Code session (local or on the web) runs every tool call in a
# non-interactive shell, and this script cannot export PATH into its caller.
# Vite+ (`vp`) is the one tool it guarantees; everything else is reached
# through it. The global CLI is installed at exactly the `vite-plus` version
# pinned in `pnpm-workspace.yaml`'s catalog, using the official installer,
# which takes the release from the npm registry, refuses a package without npm
# provenance and checks its SHA-512 `dist.integrity`. It installs under
# `$VP_HOME` (else `~/.local/share/vite-plus`) and touches no shell profile, so `vp` and `vpx`
# are then linked into `~/.local/bin`, which is on PATH in the devcontainer
# image and the web sandbox alike (a symlink to the real binary survives where
# an `export` cannot). The installer needs `vite.plus` and `viteplus.dev` on
# the session's network allowlist.
#
# From there:
#
# - `vp install --frozen-lockfile` installs the dependencies, unconditionally,
#   because a prebaked container can carry a tree built from an OLDER
#   lockfile, and stale dependencies masquerade as trunk breakage.
#   `--frozen-lockfile` is a fast no-op when in sync.
# - The global `vp` delegates development commands to the project-local
#   `vite-plus`, including inside `.claude/worktrees/*`, so each checkout runs
#   its own vitest (two physical copies corrupt its suite-collector state,
#   website#1663) without a shim.
# - Project tools run through Vite+: `vp exec fallow …` for fallow (the commit
#   gate does the same), `vpx <file>.ts` for TypeScript scripts. `tsx` stays
#   installed only because `@effect/docgen` runs it itself. Nothing else is
#   put on PATH: no shim walks a directory tree, and nothing runs a
#   `node_modules/.bin` the session did not install.
#
# After it, `vp check`, `vp run check` and `vp run -r test:unit` run with no
# manual setup.
#
# Earlier versions of this hook wrote `vp`, `fallow` and `tsx` re-exec shims
# that walked up from `$PWD` into `~/.local/bin` (and before that, symlinks
# into `node_modules/.bin`); those are removed or replaced when found (only
# ones this hook made: a symlink into a `node_modules`, or a file carrying the
# generator marker).
#
# If the installer cannot run (no network to vite.plus / viteplus.dev, or the
# catalog pin cannot be read), `vp` falls back to a one-line re-exec of this
# project's own `node_modules/vite-plus/bin/vp`, and the hook says so.
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
# Untrusted-content note: the only value read from the repository is the
# `vite-plus` catalog version, and it is used only when it is a plain
# `MAJOR.MINOR.PATCH`. It takes no other input from repo content, issue or PR
# bodies, or anything an agent could have been persuaded to write earlier in
# a session. Do not add such input without revisiting this note — it runs on
# every session start and container create.

set -uo pipefail

log() { printf '[session-start] %s\n' "$1" >&2; }

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
LOCAL_BIN="${HOME:-/root}/.local/bin"
# The installer installs under `$VP_HOME` when it is set (the Vite+ dev
# container image sets VP_HOME=/home/vp/.vite-plus and ships the CLI there),
# else under `~/.local/share/vite-plus`. Look where it put it, or the pin check
# never matches and the hook reinstalls and falls back on every run.
VP_GLOBAL_BIN="${VP_HOME:-${HOME:-/root}/.local/share/vite-plus}/bin"
# A prefix of the earlier shims' marker
# ("… (vp re-exec shim, gardeneria issue #1663)"), so those match too.
SHIM_MARKER="# generated-by: .claude/hooks/session-start.sh"

mkdir -p "$LOCAL_BIN" 2>/dev/null || log "cannot create $LOCAL_BIN; continuing"

# Replace $dest with a symlink to $src unless $dest is a real file this hook
# did not make (something deliberately installed it).
link_to() {
  src="$1"
  dest="$2"
  if [ -e "$dest" ] && [ ! -L "$dest" ] \
    && ! grep -qF "$SHIM_MARKER" "$dest" 2>/dev/null; then
    return 0
  fi
  ln -sfn "$src" "$dest" 2>/dev/null || log "could not link $(basename "$dest")"
}

# Remove a PATH entry an earlier version of this hook created.
remove_old_link() {
  dest="$LOCAL_BIN/$1"
  if [ -L "$dest" ]; then
    case "$(readlink "$dest")" in
      */node_modules/*) rm -f "$dest" 2>/dev/null && log "removed old $1 link" ;;
    esac
  elif [ -f "$dest" ] && grep -qF "$SHIM_MARKER" "$dest" 2>/dev/null; then
    rm -f "$dest" 2>/dev/null && log "removed old $1 shim"
  fi
}

# ── 1. Vite+ at the catalog pin ──────────────────────────────────────────────
VP_PIN="$(sed -nE 's/^  vite-plus: "?([0-9]+\.[0-9]+\.[0-9]+)"?$/\1/p' "$PROJECT_DIR/pnpm-workspace.yaml" 2>/dev/null | head -1)"
VP_HAVE="$("$VP_GLOBAL_BIN/vp" --version 2>/dev/null | sed -nE '1s/^vp v([0-9.]+).*$/\1/p')"
if [ -z "$VP_PIN" ]; then
  log "could not read the vite-plus catalog pin; not installing Vite+"
elif [ "$VP_HAVE" != "$VP_PIN" ]; then
  log "installing Vite+ $VP_PIN (have: ${VP_HAVE:-none})…"
  if command -v curl >/dev/null 2>&1 \
    && curl -fsSL https://vite.plus | VP_VERSION="$VP_PIN" bash >/dev/null 2>&1; then
    log "Vite+ $VP_PIN installed"
  else
    log "Vite+ installer failed (is vite.plus / viteplus.dev reachable?); continuing"
  fi
fi

remove_old_link fallow
remove_old_link tsx
if [ -x "$VP_GLOBAL_BIN/vp" ]; then
  link_to "$VP_GLOBAL_BIN/vp" "$LOCAL_BIN/vp"
  link_to "$VP_GLOBAL_BIN/vpx" "$LOCAL_BIN/vpx"
else
  # Fallback: the project's own pinned copy, by its fixed path.
  log "global Vite+ unavailable; \`vp\` runs $PROJECT_DIR's node_modules copy"
  for name in vp vpx; do
    dest="$LOCAL_BIN/$name"
    if [ -e "$dest" ] && [ ! -L "$dest" ] \
      && ! grep -qF "$SHIM_MARKER" "$dest" 2>/dev/null; then
      continue
    fi
    target="$PROJECT_DIR/node_modules/vite-plus/bin/$name"
    [ "$name" = vpx ] && target="$PROJECT_DIR/node_modules/.bin/vpx"
    printf '#!/usr/bin/env bash\n%s (%s fallback)\nexec "%s" "$@"\n' \
      "$SHIM_MARKER" "$name" "$target" >"$dest.tmp" \
      && chmod +x "$dest.tmp" && mv -f "$dest.tmp" "$dest" \
      || { rm -f "$dest.tmp" 2>/dev/null; log "could not write the $name fallback"; }
  done
fi

# ── 2. Dependencies ─────────────────────────────────────────────────────────
# `vp install` uses the `packageManager` pin. The fallback `vp` points into
# node_modules, which may not exist yet, so only the global CLI installs;
# without it, pnpm does, through corepack when pnpm itself is missing.
if [ -f "$PROJECT_DIR/pnpm-lock.yaml" ]; then
  log "syncing dependencies against the lockfile…"
  if [ -x "$VP_GLOBAL_BIN/vp" ]; then
    (cd "$PROJECT_DIR" && "$VP_GLOBAL_BIN/vp" install --frozen-lockfile >/dev/null 2>&1) \
      || log "dependency install failed; continuing"
  else
    if ! command -v pnpm >/dev/null 2>&1; then
      log "pnpm not found; enabling corepack…"
      (corepack enable >/dev/null 2>&1 && cd "$PROJECT_DIR" && corepack install >/dev/null 2>&1) \
        || log "corepack could not provide pnpm; continuing"
    fi
    (cd "$PROJECT_DIR" && pnpm install --frozen-lockfile >/dev/null 2>&1) \
      || log "dependency install failed; continuing"
  fi
fi

exit 0
