/**
 * AuthKit's authorization-code flow as the core's `OAuthService` and
 * `SsoService`: the browser goes to `/user_management/authorize` (the hosted
 * AuthKit UI, a social provider, or an SSO connection), comes back with a
 * code, and the `authorization_code` grant signs the user in. The `state` is
 * spent once through the core `OAuthStateStore` (stored as its digest), and
 * the PKCE verifier is derived from it under the root secret, never stored.
 *
 * WorkOS holds the connections, so registering one, SAML metadata and
 * linking provider accounts by hand are refused.
 *
 * @since 0.1.0
 */
import * as Clock from "effect/Clock";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { Digest, type Mac, SecureRandom } from "effect/crypto";
import { Base64Url } from "effect/encoding";
import * as Auth from "@thomasfosterau/effect-auth";
import { WorkOSAuthenticate, WorkOSSessions, type WorkOSIssued } from "./Session.ts";
import { unsupported, WorkOSClient } from "./WorkOS.ts";

const STATE_TTL_MS = 10 * 60 * 1000;

/**
 * The social providers WorkOS names, by the name an app passes to
 * `generateAuthorizationUrl`.
 *
 * @since 0.1.0
 * @category constants
 */
export const SOCIAL_PROVIDERS = {
  authkit: "authkit",
  google: "GoogleOAuth",
  microsoft: "MicrosoftOAuth",
  github: "GitHubOAuth",
  apple: "AppleOAuth",
} as const;

/**
 * The `/authorize` parameter naming what to sign in with: a provider from
 * {@link SOCIAL_PROVIDERS}, `connection:<id>` for an SSO connection, or
 * `organization:<id>` for an organization's connection.
 *
 * @since 0.1.0
 * @category utils
 */
export const authorizeTarget = (
  provider: string,
): Option.Option<Readonly<Record<string, string>>> => {
  const social = R.get<string, string>(SOCIAL_PROVIDERS, provider);
  if (Option.isSome(social)) return Option.some({ provider: social.value });
  if (provider.startsWith("connection:") && provider.length > 11) {
    return Option.some({ connection_id: provider.slice(11) });
  }
  if (provider.startsWith("organization:") && provider.length > 13) {
    return Option.some({ organization_id: provider.slice(13) });
  }
  return Option.none();
};

const asSso = (cause: unknown) =>
  Effect.fail(new Auth.SsoError({ message: "WorkOS SSO sign-in failed", cause }));

/** The `authorizeTarget` provider for a connection or organization id. */
const connectionOf = (providerId?: string) =>
  providerId?.startsWith("conn_")
    ? Option.some(`connection:${providerId}`)
    : providerId?.startsWith("org_")
      ? Option.some(`organization:${providerId}`)
      : Option.none();

/** The authorization-code half both services share. */
const makeFlow = Effect.fn("WorkOS.AuthKit.makeFlow")(function* () {
  const workos = yield* WorkOSClient;
  const { config } = workos;
  const sessions = yield* WorkOSSessions;
  const { authenticate } = yield* WorkOSAuthenticate;
  const hooks = yield* Auth.Hooks;
  const random = yield* SecureRandom.SecureRandom;
  const digest = yield* Digest.Digest;
  const hash = yield* Auth.tokenHasher;
  const verifierFor = yield* Auth.RootSecret.pkceVerifier;
  const states = Auth.OAuth.hashedStateStore(yield* Auth.OAuth.OAuthStateStore, hash);

  const begin = (provider: string, returnTo?: string) =>
    Effect.gen(function* () {
      const target = authorizeTarget(provider);
      if (Option.isNone(target)) {
        return yield* new Auth.OAuthProviderError({
          message: `Unknown WorkOS provider: ${provider}`,
          provider,
        });
      }
      if (Option.isNone(config.redirectUri)) {
        return yield* new Auth.OAuthProviderError({
          message: "The WorkOS backend needs a redirectUri for AuthKit sign-in",
          provider,
        });
      }
      const state = Base64Url.encode(yield* random.randomBytes(32));
      const challenge = yield* Auth.OAuth.pkceChallenge(yield* verifierFor(state)).pipe(
        Effect.provideService(Digest.Digest, digest),
      );
      const now = yield* Clock.currentTimeMillis;
      yield* states.create({
        state,
        provider,
        ...(returnTo !== undefined && { returnTo }),
        createdAt: now,
        expiresAt: now + STATE_TTL_MS,
      });
      const url = new URL("/user_management/authorize", config.baseUrl);
      const params = {
        client_id: config.clientId,
        redirect_uri: config.redirectUri.value,
        response_type: "code",
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
        ...target.value,
      };
      url.search = new URLSearchParams(params).toString();
      return { url: url.toString(), state };
    });

  /** Spend `state`, exchange `code`, and issue the session. */
  const complete = (state: string, code: string, method: "oauth" | "sso") =>
    Effect.gen(function* () {
      const consumed = yield* states.consume(state);
      if (Option.isNone(consumed)) {
        return yield* new Auth.OAuthStateNotFoundError({
          message: "Unknown or spent state",
          state,
        });
      }
      const entry = consumed.value;
      if ((yield* Clock.currentTimeMillis) > entry.expiresAt) {
        return yield* new Auth.OAuthStateExpiredError({ message: "The sign-in expired", state });
      }
      const auth = yield* authenticate({
        grant_type: "authorization_code",
        code,
        code_verifier: yield* verifierFor(state),
      }).pipe(
        Effect.mapError(
          (error) =>
            new Auth.OAuthProviderError({
              message: "WorkOS refused the authorization code",
              provider: entry.provider,
              cause: error,
            }),
        ),
      );
      const issued: WorkOSIssued = yield* sessions.issue(auth);
      yield* hooks.afterSignIn({
        user: issued.user,
        session: issued.session,
        token: issued.token,
        method,
      });
      return { entry, issued, email: Auth.normalizeEmail(auth.user.email) };
    });

  return { begin, complete, config };
});

const unsupportedOAuth = (what: string) => Effect.fail(unsupported(`OAuthService.${what}`));

/**
 * The core `OAuthService` over AuthKit. `generateAuthorizationUrl` takes a
 * provider from {@link SOCIAL_PROVIDERS} (`"authkit"` for the hosted UI),
 * `connection:<id>` or `organization:<id>`; `signInWithCallback` completes it.
 * The `OAuthAccount` it answers names the WorkOS user and holds no provider
 * token (`accessToken` is empty): WorkOS keeps them.
 *
 * @since 0.1.0
 * @category layers
 */
export const oauthLayer: Layer.Layer<
  Auth.OAuth.OAuthService,
  never,
  | WorkOSClient
  | WorkOSSessions
  | WorkOSAuthenticate
  | Auth.Hooks
  | Auth.OAuth.OAuthStateStore
  | Auth.RootSecret.RootSecret
  | SecureRandom.SecureRandom
  | Digest.Digest
  | Mac.Mac
> = Layer.effect(
  Auth.OAuth.OAuthService,
  Effect.gen(function* () {
    const flow = yield* makeFlow();
    return Auth.OAuth.OAuthService.of({
      generateAuthorizationUrl: (provider, options) => flow.begin(provider, options?.returnTo),
      signInWithCallback: (state, code) =>
        Effect.map(flow.complete(state, code, "oauth"), ({ entry, issued, email }) => ({
          user: issued.user,
          account: {
            id: `workos:${entry.provider}:${issued.user.id}`,
            userId: issued.user.id,
            provider: entry.provider,
            providerId: issued.user.id,
            email,
            accessToken: "",
            createdAt: issued.session.createdAt.getTime(),
            updatedAt: issued.session.createdAt.getTime(),
          },
          isNewUser: false,
          ...(entry.returnTo !== undefined && { returnTo: entry.returnTo }),
          session: issued.session,
          token: issued.token,
        })),
      handleCallback: () => unsupportedOAuth("handleCallback"),
      linkAccount: () => unsupportedOAuth("linkAccount"),
      unlinkAccount: () => unsupportedOAuth("unlinkAccount"),
      refreshAccessToken: () => unsupportedOAuth("refreshAccessToken"),
    });
  }),
);

const ssoUnsupported = (what: string) =>
  Effect.fail(new Auth.SsoError({ message: `${what} is managed in the WorkOS dashboard` }));

const toSso = <A, R>(
  effect: Effect.Effect<
    A,
    | Auth.HookError
    | Auth.SsoError
    | Auth.OAuthProviderError
    | Auth.OAuthStateNotFoundError
    | Auth.OAuthStateExpiredError,
    R
  >,
): Effect.Effect<A, Auth.HookError | Auth.SsoError, R> =>
  Effect.catchTags(effect, {
    OAuthProviderError: asSso,
    OAuthStateNotFoundError: asSso,
    OAuthStateExpiredError: asSso,
  });

/**
 * The core `SsoService` over WorkOS SSO. `signIn` takes the connection or
 * organization id as `providerId` (`conn_…` or `org_…`); an email or domain
 * alone is refused, since WorkOS routes those itself through the hosted
 * AuthKit UI (`OAuthService` with `"authkit"`). The `provider` a callback
 * answers describes the WorkOS connection, with no secret in it.
 *
 * @since 0.1.0
 * @category layers
 */
export const ssoLayer: Layer.Layer<
  Auth.SsoService,
  never,
  | WorkOSClient
  | WorkOSSessions
  | WorkOSAuthenticate
  | Auth.Hooks
  | Auth.OAuth.OAuthStateStore
  | Auth.RootSecret.RootSecret
  | SecureRandom.SecureRandom
  | Digest.Digest
  | Mac.Mac
> = Layer.effect(
  Auth.SsoService,
  Effect.gen(function* () {
    const flow = yield* makeFlow();
    return Auth.SsoService.of({
      registerProvider: () => ssoUnsupported("Registering an SSO connection"),
      registerSamlProvider: () => ssoUnsupported("Registering a SAML connection"),
      resolveProviderForEmail: () => Effect.succeedNone,
      samlMetadata: () => ssoUnsupported("SAML metadata"),
      handleSamlCallback: () => ssoUnsupported("The SAML callback"),
      signIn: (selector) =>
        Option.match(connectionOf(selector.providerId), {
          onNone: () =>
            Effect.fail(
              new Auth.SsoError({
                message: "WorkOS SSO needs a connection or organization id (conn_… or org_…)",
              }),
            ),
          onSome: (target) =>
            Effect.catchTag(flow.begin(target), "OAuthProviderError", (cause) =>
              Effect.fail(new Auth.SsoError({ message: cause.message, cause })),
            ),
        }),
      handleCallback: (state, code) =>
        toSso(
          Effect.map(flow.complete(state, code, "sso"), ({ entry, issued }) => ({
            user: issued.user,
            isNewUser: false,
            provider: {
              id: entry.provider.slice(entry.provider.indexOf(":") + 1),
              issuer: flow.config.baseUrl,
              domain: "",
              protocol: "oidc" as const,
              clientId: flow.config.clientId,
              clientSecret: "",
              redirectUri: Option.getOrElse(flow.config.redirectUri, () => ""),
              authorizationEndpoint: `${flow.config.baseUrl}/user_management/authorize`,
              tokenEndpoint: `${flow.config.baseUrl}/user_management/authenticate`,
              scopes: [],
              usePKCE: true,
              userId: "",
              createdAt: issued.session.createdAt.getTime(),
            },
            session: issued.session,
            token: issued.token,
          })),
        ),
    });
  }),
);
