/**
 * The SHA-256 hex digest `hashToken` computes, synchronously, for tests that
 * build a stored id or compare one outside an Effect. Test support only, so
 * excluded from the build; the library hashes through `effect/crypto`.
 */
import { createHash } from "node:crypto";

export const sha256Hex = (value: string): string =>
  createHash("sha256").update(value).digest("hex");
