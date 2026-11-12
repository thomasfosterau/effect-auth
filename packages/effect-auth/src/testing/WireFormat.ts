/**
 * Test helpers for the RFC tier's wire format (#205): the endpoints whose
 * format another specification fixes answer their own media type, never a
 * JSON:API document.
 *
 * Never published (`tsconfig.json` excludes this file; the rest of `src/testing/`
 * is the public `./testing` subpath).
 */
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import { expect } from "vite-plus/test";

/** The JSON:API media type, which no RFC-tier endpoint answers. */
export const JSON_API_MEDIA_TYPE = "application/vnd.api+json";

/** The top-level members that make a body a JSON:API document. */
const JSON_API_MEMBERS = ["data", "errors", "jsonapi"] as const;

const JsonObject = Schema.Record(Schema.String, Schema.Json);

/** A response's media type, without its parameters (`; charset=…`). */
export const mediaTypeOf = (response: Response): string | undefined =>
  response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();

/**
 * Assert that `response` answers `mediaType` with a JSON object that carries
 * each of `members` and none of a JSON:API document's top-level members.
 * Answers the object, for the test to read further.
 */
export const expectSpecJson = async (
  response: Response,
  mediaType: string,
  members: ReadonlyArray<string>,
): Promise<typeof JsonObject.Type> => {
  expect(mediaTypeOf(response)).toBe(mediaType);
  const body = Schema.decodeUnknownSync(JsonObject)(await response.json());
  expect(members.filter((member) => !P.hasProperty(body, member))).toEqual([]);
  expect(JSON_API_MEMBERS.filter((member) => P.hasProperty(body, member))).toEqual([]);
  return body;
};
