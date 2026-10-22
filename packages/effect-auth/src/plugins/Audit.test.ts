import { describe, expect, it } from "vite-plus/test";
import { Effect, Layer, Logger } from "effect";
import * as Entity from "../Entity.ts";
import { Hooks, recordWrite, type WriteEvent } from "../Hooks.ts";
import * as System from "../System.ts";
import { AuditPlugin } from "./Audit.ts";

/** Run `effect` under the Audit plugin, collecting every log record's message. */
const captureLogs = <A, E>(effect: Effect.Effect<A, E, Hooks>) => {
  const records: Array<ReadonlyArray<unknown>> = [];
  const collector = Logger.make((options) => {
    records.push(options.message as ReadonlyArray<unknown>);
  });
  return Effect.runPromise(
    effect.pipe(
      Effect.provide(
        Layer.merge(AuditPlugin.pipe(Layer.provide(Hooks.Default)), Logger.layer([collector])),
      ),
    ),
  ).then(() => records);
};

describe("AuditPlugin afterWrite (#362)", () => {
  const resource = Entity.ref("Page", "p-1");

  it.each([
    {
      who: "a system principal",
      principal: System.ref("translation-pipeline"),
      formatted: 'System::"translation-pipeline"',
      system: true,
    },
    {
      who: "a user",
      principal: Entity.ref("User", "u-1"),
      formatted: 'User::"u-1"',
      system: false,
    },
  ])("logs a write recorded by $who with the acting principal", async (row) => {
    const event: WriteEvent = { principal: row.principal, action: "page:write", resource };

    const records = await captureLogs(recordWrite(event));

    expect(records).toEqual([
      [
        "auth.write",
        {
          principal: row.formatted,
          system: row.system,
          action: "page:write",
          resource: 'Page::"p-1"',
        },
      ],
    ]);
  });

  it("recordWrite with no plugin is a no-op", async () => {
    await expect(
      Effect.runPromise(
        recordWrite({ principal: System.ref("job"), action: "page:write", resource }).pipe(
          Effect.provide(Hooks.Default),
        ),
      ),
    ).resolves.toBeUndefined();
  });
});
