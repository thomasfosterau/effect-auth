import { describe, expect, it } from "vite-plus/test";
import * as Exit from "effect/Exit";
import * as Schema from "effect/Schema";
import * as S from "./HttpApiSchema.ts";

describe("request input bounds", () => {
  it("refuses a decoded string over the bound and accepts one at it", () => {
    const decode = Schema.decodeUnknownExit(S.NameInput);
    expect(Exit.isSuccess(decode("n".repeat(S.MAX_NAME_LENGTH)))).toBe(true);
    expect(Exit.isFailure(decode("n".repeat(S.MAX_NAME_LENGTH + 1)))).toBe(true);
  });

  it("encodes a stored value of any size, so a record above a bound stays readable", () => {
    const long = "n".repeat(S.MAX_NAME_LENGTH * 10);
    expect(Schema.encodeUnknownExit(S.NameInput)(long)).toEqual(Exit.succeed(long));
    const bag = { notes: "m".repeat(S.MAX_ATTRIBUTES_BYTES * 2) };
    expect(Exit.isSuccess(Schema.encodeUnknownExit(S.AttributesInput)(bag))).toBe(true);
  });

  it("counts an attribute bag in UTF-8 bytes of its JSON", () => {
    const decode = Schema.decodeUnknownExit(S.AttributesInput);
    // `{"a":""}` is 8 bytes; each "é" is two.
    const within = { a: "é".repeat((S.MAX_ATTRIBUTES_BYTES - 8) / 2) };
    expect(Exit.isSuccess(decode(within))).toBe(true);
    expect(Exit.isFailure(decode({ ...within, b: 1 }))).toBe(true);
  });
});
