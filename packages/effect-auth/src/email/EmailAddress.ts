import * as Schema from "effect/Schema";

/** Schema for an email address on the wire: a plain string. */
export const EmailAddress = Schema.String;
export type EmailAddress = typeof EmailAddress.Type;
