import { Schema } from "effect";

/** Schema for an email address on the wire: a plain string. */
export const EmailAddress = Schema.String;
export type EmailAddress = typeof EmailAddress.Type;
