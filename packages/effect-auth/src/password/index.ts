export * from "./HaveIBeenPwned.ts";
export * from "./Password.ts";
// Named, not `export *`: `PasswordReset.make` builds a `PasswordResetService`,
// and through this barrel it would read as `Password.make`, the cluster's
// hasher (#259). `PasswordResetService.layer` is the public constructor, as in
// the `email/` and `multifactor/` barrels.
export {
  type PasswordResetToken,
  PasswordResetStore,
  PasswordResetUserStore,
  type PasswordResetConfig,
  type PasswordResetResult,
  PasswordResetService,
} from "./PasswordReset.ts";
