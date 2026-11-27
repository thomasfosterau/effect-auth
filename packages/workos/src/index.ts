/**
 * WorkOS as an effect-auth backend: WorkOS keeps the users, passwords and
 * sessions, and the core's services, hooks and HTTP tier run over it.
 * {@link layer} provides what `Http.make` needs.
 *
 * @since 0.1.0
 */
import * as Layer from "effect/Layer";
import { FetchHttpClient, type HttpClient } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";
import * as AuthKit from "./AuthKit.ts";
import * as Codes from "./Codes.ts";
import * as EmailPassword from "./EmailPassword.ts";
import * as Session from "./Session.ts";
import * as Users from "./Users.ts";
import { WorkOSClient, type WorkOSConfig } from "./WorkOS.ts";

/** @since 0.1.0 */
export * as AuthKit from "./AuthKit.ts";
/** @since 0.1.0 */
export * as Authorization from "./Authorization.ts";
/** @since 0.1.0 */
export * as Codes from "./Codes.ts";
/** @since 0.1.0 */
export * as EmailPassword from "./EmailPassword.ts";
/** @since 0.1.0 */
export * as Events from "./Events.ts";
/** @since 0.1.0 */
export * as Schemas from "./Schemas.ts";
/** @since 0.1.0 */
export * as Seal from "./Seal.ts";
/** @since 0.1.0 */
export * as Session from "./Session.ts";
/** @since 0.1.0 */
export * as Users from "./Users.ts";
/** @since 0.1.0 */
export * as Webhook from "./Webhook.ts";
/** @since 0.1.0 */
export * as WorkOS from "./WorkOS.ts";

/**
 * Every service {@link layer} provides.
 *
 * @since 0.1.0
 * @category models
 */
export type Services =
  | WorkOSClient
  | Session.WorkOSSessions
  | Session.WorkOSAuthenticate
  | Auth.SessionService.SessionService
  | Auth.UserStore.UserStore
  | Auth.Identifier.IdentifierStore
  | Auth.User.UserService
  | Auth.Email.EmailPasswordService
  | Auth.Email.EmailVerificationService
  | Auth.Email.EmailOtpService
  | Auth.Password.PasswordResetService
  | Auth.Password.PasswordHasher
  | Auth.AuthLifecycle.AuthLifecycleService
  | Auth.OAuth.OAuthService
  | Auth.Sso.SsoService;

/**
 * What the app provides beside {@link layer}: its `Hooks` (plugins), the
 * `OAuthStateStore` and `RootSecret` the AuthKit sign-in needs. Optional and
 * read where the layer is built: `Session.RevokedSessions` (revocations seen
 * before an access token expires), an `EmailSender` (required with
 * `delivery: "app"`) and `OutboundLimits`.
 *
 * @since 0.1.0
 * @category models
 */
export type Requirements =
  | Auth.Hooks.Hooks
  | Auth.OAuth.OAuthStateStore
  | Auth.RootSecret.RootSecret;

/**
 * The WorkOS backend over the `HttpClient` in context, for a custom
 * transport or a test.
 *
 * @since 0.1.0
 * @category layers
 */
export const layerHttpClient = (
  config: WorkOSConfig,
): Layer.Layer<Services, never, Requirements | HttpClient.HttpClient> => {
  const client = WorkOSClient.layerHttpClient(config);
  const sessions = Session.layer.pipe(Layer.provideMerge(client));
  const users = Layer.mergeAll(
    Users.userStoreLayer,
    Users.identifierStoreLayer,
    Users.userServiceLayer,
  ).pipe(Layer.provide(client));
  const flows = Layer.mergeAll(
    EmailPassword.emailPasswordLayer,
    Codes.emailVerificationLayer,
    Codes.passwordResetLayer,
    Codes.magicAuthLayer,
    AuthKit.oauthLayer,
    AuthKit.ssoLayer,
  ).pipe(Layer.provide(Auth.PlatformCrypto.layer), Layer.provideMerge(sessions));
  const lifecycle = EmailPassword.authLifecycleLayer.pipe(
    Layer.provideMerge(Layer.merge(flows, users)),
  );
  return Layer.mergeAll(lifecycle, EmailPassword.refusingHasherLayer);
};

/**
 * The WorkOS backend over the platform `fetch`: every service `Http.make`
 * needs except the app's `Hooks`, plus `OAuthService` and `SsoService` over
 * AuthKit.
 *
 * @since 0.1.0
 * @category layers
 */
export const layer = (config: WorkOSConfig): Layer.Layer<Services, never, Requirements> =>
  layerHttpClient(config).pipe(Layer.provide(FetchHttpClient.layer));
