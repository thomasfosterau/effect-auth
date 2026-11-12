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

/**
 * An extra task: its command, or its command and the environment variables it
 * reads. A cached task sees only the variables it declares, so a variable the
 * command needs (a test server's `DATABASE_URL`, `CI`) goes in `env`, which
 * passes it through and fingerprints it: a run without it is never replayed
 * for a run with it (#766).
 */
type ExtraTask = string | { readonly command: string; readonly env: ReadonlyArray<string> };

const extraTask = (task: ExtraTask) =>
  typeof task === "string"
    ? { command: task, dependsOn: [builtDependencies] }
    : { command: task.command, dependsOn: [builtDependencies], cache: { env: [...task.env] } };

export const packageTasks = (commands: {
  readonly build: string;
  readonly check: string;
  readonly test?: string;
  /** Extra tasks, each built behind the same `build` dependencies. */
  readonly extra?: Readonly<Record<string, ExtraTask>>;
}) => ({
  tasks: {
    build: { command: commands.build, dependsOn: [builtDependencies] },
    check: { command: commands.check, dependsOn: [builtDependencies] },
    "test:unit": { command: commands.test ?? "vp test run", dependsOn: [builtDependencies] },
    ...Object.fromEntries(
      Object.entries(commands.extra ?? {}).map(([name, task]) => [name, extraTask(task)]),
    ),
  },
});
