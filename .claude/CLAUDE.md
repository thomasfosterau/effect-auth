# Claude Code in effect-auth

This file holds only what is specific to Claude Code. The project guidance every agent and contributor follows is imported at the end: [AGENTS.md](../AGENTS.md) (conventions, pitfalls, the Verification gates, the work tracker), [CONTRIBUTING.md](../CONTRIBUTING.md) (setup, commands, branch / PR / changeset rules) and [README.md](../README.md) (what the repository is, the package table). Don't restate their content here; change it there.

## Hooks (`.claude/settings.json`)

- **SessionStart** ([hooks/session-start.sh](hooks/session-start.sh), also the devcontainer's `postCreateCommand`) installs the global Vite+ CLI at the catalog's `vite-plus` pin with the official installer (npm-provenance and SHA-512 checked; it needs `vite.plus` and `viteplus.dev` on the environment's allowlist), links `vp` and `vpx` into `~/.local/bin` (the CLI lives under `$VP_HOME` when set, as in the Vite+ container image, else `~/.local/share/vite-plus`), and runs `vp install --frozen-lockfile`. The global `vp` delegates to each checkout's own `vite-plus`, worktrees included. Nothing else is put on PATH; if the installer can't run, `vp` falls back to this checkout's `node_modules` copy. It hydrates no secrets; none are needed.
- **PreToolUse** ([hooks/fallow-gate.sh](hooks/fallow-gate.sh)) blocks `git commit` / `git push` when `fallow audit --base origin/trunk` (run through `vp exec fallow`) fails. It runs only in this checkout and its `.claude/worktrees/*`; for any other tree it skips the audit with a notice, without running that tree's tooling. It reads the coverage map on disk and never refreshes it, so run `vp run test:coverage` before you commit.
- **PostToolUse** runs `vp fmt --write` on every file you edit (`.ts`, `.js`, `.json`, `.md`, `.svelte`, …), so edits are reformatted after you write them. It formats `CHANGELOG.md` too if you edit one; Changesets owns those files, so don't.

No plugins are configured in `.claude/settings.json`, and there is no `.claude/rules/` directory.

## Sessions

- Work in a git worktree under `.claude/worktrees/` (one branch per issue). The fallow gate covers those, and the global `vp` delegates to each worktree's own `vite-plus`.
- In a cloud session, `vp run check:dist` and `pnpm audit` need registry access, and the SessionStart installer needs `vite.plus` / `viteplus.dev` allowed. If a gate can't run, say which and why in the PR body.
- Each `packages/*/CLAUDE.md` is one line, `@AGENTS.md`: the package's guidance lives in its `AGENTS.md`, which Claude loads when it works in that directory.
- `fallow hooks install` / `fallow agent install` regenerate the fallow block in `AGENTS.md`, which is where it belongs. Don't let either append `@AGENTS.md` to a `CLAUDE.md`: this file already imports it.

## Tools

- Use the `gh` CLI for GitHub operations, even when GitHub MCP tools are available.

@../AGENTS.md
@../CONTRIBUTING.md
@../README.md
