/**
 * The per-package task triple every workspace package declares in its own
 * `vite.config.ts`: `build`, `check` (the type gates) and `test:unit`.
 *
 * Each task first runs `build` in the workspace packages this one depends on.
 * A package's `exports` point at its gitignored `dist/`, so a dependent cannot
 * type-check, test or build against a sibling that has not been built — the
 * graph edge makes that ordering the task runner's job instead of a manual
 * step, which is what lets a fresh checkout run `vp run check` and
 * `vp run -r test:unit` straight after `vp install`.
 */
const builtDependencies = {
  task: "build",
  from: ["dependencies", "devDependencies"],
} as const;

export const packageTasks = (commands: {
  readonly build: string;
  readonly check: string;
  readonly test?: string;
}) => ({
  tasks: {
    build: { command: commands.build, dependsOn: [builtDependencies] },
    check: { command: commands.check, dependsOn: [builtDependencies] },
    "test:unit": { command: commands.test ?? "vp test run", dependsOn: [builtDependencies] },
  },
});
