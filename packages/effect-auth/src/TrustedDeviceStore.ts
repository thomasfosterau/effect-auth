/**
 * The trusted-device record and store, apart from `TrustedDevice.ts` so the
 * flows that revoke devices (password change and reset, multi-factor
 * disable) can import the store without importing the gate.
 *
 * @internal
 */
import { Context, type Effect } from "effect";
import type * as Errors from "./Errors.ts";

/**
 * Trusted-device record stored in the database. The raw token is never
 * persisted; only its SHA-256 digest is kept for constant-time revocation.
 */
export interface TrustedDeviceRecord {
  /** SHA-256 hex digest of the raw token (`hashToken(rawToken)`). */
  readonly tokenHash: string;
  readonly userId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Persistence interface for trusted-device tokens. Keyed by `tokenHash`
 * (SHA-256 of the raw token half of the cookie).
 */
export class TrustedDeviceStore extends Context.Service<
  TrustedDeviceStore,
  {
    readonly upsert: (
      record: TrustedDeviceRecord,
    ) => Effect.Effect<TrustedDeviceRecord, Errors.AuthError>;
    readonly getByTokenHash: (
      tokenHash: string,
    ) => Effect.Effect<TrustedDeviceRecord | null, Errors.AuthError>;
    readonly delete: (tokenHash: string) => Effect.Effect<void, Errors.AuthError>;
    /** Revoke every device token for a user (password change, 2FA disable, etc.). */
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/TrustedDeviceStore") {}
