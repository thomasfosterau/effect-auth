/**
 * Enterprise SSO (single sign-on) — OIDC relying party with domain routing.
 *
 * Lets tenants bring their own identity provider: register a per-organization
 * OIDC connection, route sign-ins by email domain, and provision users (and,
 * optionally, organization members) on first login. An SSO connection is, under
 * the hood, a dynamically-registered OAuth provider, so this module reuses the
 * OAuth machinery in {@link module:oauth} — {@link makeOAuthProvider},
 * {@link discoverOAuthEndpoints}, and the shared {@link OAuthStateStore}.
 *
 * SAML is out of scope for now; the store shape carries a `protocol` field so a
 * SAML connection type can be added later without a migration.
 *
 * @module sso
 */
import { Context, Data, Effect, Layer } from "effect";
import { AuthError } from "./Errors.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import { SessionManager } from "./Session.ts";
import { OrganizationStore, type Member } from "./Organization.ts";
import {
  makeOAuthProvider,
  discoverOAuthEndpoints,
  OAuthStateStore,
  OAuthUserStore,
  type OAuthProviderConfig,
} from "./OAuth.ts";
import * as crypto from "node:crypto";
import type * as Types from "./Types.ts";

/** Failure to register, resolve, or complete an SSO sign-in. */
export class SsoError extends Data.TaggedError("SsoError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * A registered SSO connection. Endpoints may be supplied directly or populated
 * from the issuer's discovery document at registration time.
 */
export interface SsoProvider {
  readonly id: string;
  /** OIDC issuer identifier (`iss`). */
  readonly issuer: string;
  /** Email domain that routes to this provider (normalized, lowercase). */
  readonly domain: string;
  readonly protocol: "oidc";
  readonly clientId: string;
  readonly clientSecret: string;
  /** Where the IdP redirects after authorization (this app's callback URL). */
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly jwksEndpoint?: string;
  readonly scopes: readonly string[];
  readonly usePKCE: boolean;
  /** Organization to add the user to on first login (with {@link defaultRole}). */
  readonly organizationId?: string;
  /** User id of the admin who registered the connection. */
  readonly userId: string;
  /** Epoch milliseconds. */
  readonly createdAt: number;
}

/** Persistent registry of SSO connections. */
export interface SsoProviderStoreShape {
  readonly create: (provider: SsoProvider) => Effect.Effect<SsoProvider, AuthError>;
  readonly getById: (id: string) => Effect.Effect<SsoProvider | null, AuthError>;
  readonly getByDomain: (domain: string) => Effect.Effect<SsoProvider | null, AuthError>;
  readonly list: () => Effect.Effect<ReadonlyArray<SsoProvider>, AuthError>;
}

export class SsoProviderStore extends Context.Service<SsoProviderStore, SsoProviderStoreShape>()(
  "@effect-auth/SsoProviderStore",
) {}

/** Input to {@link SsoServiceShape.registerProvider}. */
export interface RegisterProviderInput {
  readonly issuer: string;
  readonly domain: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  /** Discover `authorization`/`token`/`userinfo`/`jwks` endpoints from the issuer. */
  readonly discover?: boolean;
  readonly authorizationEndpoint?: string;
  readonly tokenEndpoint?: string;
  readonly userInfoEndpoint?: string;
  readonly jwksEndpoint?: string;
  readonly scopes?: readonly string[];
  readonly usePKCE?: boolean;
  readonly organizationId?: string;
}

/** Result of a completed SSO sign-in. */
export interface SsoSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  readonly provider: SsoProvider;
}

/** Where to start an SSO sign-in from. */
export interface SsoSignInSelector {
  readonly email?: string;
  readonly providerId?: string;
  readonly domain?: string;
}

export interface SsoServiceShape {
  /**
   * Register (or discover + register) an SSO connection. The registrar
   * (`registrarUserId`) is recorded on the connection; gate this behind an
   * admin check at the HTTP layer.
   */
  readonly registerProvider: (
    registrarUserId: string,
    input: RegisterProviderInput,
  ) => Effect.Effect<SsoProvider, SsoError | AuthError, SsoProviderStore>;

  /**
   * Resolve the connection an email address routes to, by domain. Returns
   * `null` when no connection matches.
   */
  readonly resolveProviderForEmail: (
    email: string,
  ) => Effect.Effect<SsoProvider | null, AuthError, SsoProviderStore>;

  /**
   * Begin an SSO sign-in: resolve the connection (by `providerId`, `domain`, or
   * the domain of `email`) and return the IdP authorization URL to redirect to.
   */
  readonly signIn: (
    selector: SsoSignInSelector,
  ) => Effect.Effect<
    { readonly url: string; readonly state: string },
    SsoError | AuthError,
    SsoProviderStore | OAuthStateStore
  >;

  /**
   * Complete the SSO callback: exchange the code, verify the profile,
   * find-or-create the user by verified email, optionally add them to the
   * connection's organization, and issue a session.
   */
  readonly handleCallback: (
    state: string,
    code: string,
  ) => Effect.Effect<
    SsoSignInResult,
    SsoError | AuthError | HookError,
    SsoProviderStore | OAuthStateStore | OAuthUserStore | SessionManager | Hooks
  >;
}

export class SsoService extends Context.Service<SsoService, SsoServiceShape>()(
  "@effect-auth/SsoService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: SsoConfig = {}) =>
    Layer.effect(SsoService, makeSsoService(config));
}

/** Configuration for {@link makeSsoService}. */
export interface SsoConfig {
  /** Default scopes when a connection doesn't specify any. */
  readonly defaultScopes?: readonly string[];
  /** Role granted when auto-adding a user to a connection's organization. */
  readonly defaultRole?: string;
}

const normalizeDomain = (value: string): string => value.trim().toLowerCase();
const domainOf = (email: string): string => normalizeDomain(email.split("@")[1] ?? "");

/** The `sso:`-prefixed provider name stored in OAuth state, encoding the id. */
const stateProviderName = (id: string): string => `sso:${id}`;
const idFromStateProvider = (name: string): string | null =>
  name.startsWith("sso:") ? name.slice(4) : null;

/** Build the OAuth provider config for an SSO connection. */
const toOAuthConfig = (provider: SsoProvider): OAuthProviderConfig => ({
  clientId: provider.clientId,
  clientSecret: provider.clientSecret,
  redirectUri: provider.redirectUri,
  authorizationEndpoint: provider.authorizationEndpoint,
  tokenEndpoint: provider.tokenEndpoint,
  scopes: provider.scopes,
  ...(provider.userInfoEndpoint !== undefined
    ? { userInfoEndpoint: provider.userInfoEndpoint }
    : {
        // No userinfo endpoint: resolve the profile from the verified id_token.
        getUserInfoFromIdToken: true,
        ...(provider.jwksEndpoint !== undefined && { jwksEndpoint: provider.jwksEndpoint }),
        issuer: provider.issuer,
      }),
});

export const makeSsoService = (config: SsoConfig = {}): Effect.Effect<SsoServiceShape, never> => {
  const defaultScopes = config.defaultScopes ?? ["openid", "email", "profile"];
  const defaultRole = config.defaultRole ?? "member";

  const resolveProvider = (selector: SsoSignInSelector) =>
    Effect.gen(function* () {
      const store = yield* SsoProviderStore;
      if (selector.providerId !== undefined) {
        const p = yield* store.getById(selector.providerId);
        if (p === null) {
          return yield* new SsoError({ message: "SSO provider not found" });
        }
        return p;
      }
      const domain =
        selector.domain !== undefined
          ? normalizeDomain(selector.domain)
          : selector.email !== undefined
            ? domainOf(selector.email)
            : "";
      if (domain === "") {
        return yield* new SsoError({ message: "An email, domain, or providerId is required" });
      }
      const p = yield* store.getByDomain(domain);
      if (p === null) {
        return yield* new SsoError({ message: `No SSO provider for domain "${domain}"` });
      }
      return p;
    });

  return Effect.succeed({
    registerProvider: (registrarUserId, input) =>
      Effect.gen(function* () {
        const store = yield* SsoProviderStore;

        const discovered = input.discover
          ? yield* discoverOAuthEndpoints(input.issuer).pipe(
              Effect.mapError((e) => new SsoError({ message: e.message, cause: e })),
            )
          : undefined;

        const authorizationEndpoint =
          input.authorizationEndpoint ?? discovered?.authorizationEndpoint;
        const tokenEndpoint = input.tokenEndpoint ?? discovered?.tokenEndpoint;
        if (authorizationEndpoint === undefined || tokenEndpoint === undefined) {
          return yield* new SsoError({
            message:
              "authorizationEndpoint and tokenEndpoint are required (set `discover: true` or pass them explicitly)",
          });
        }
        const userInfoEndpoint = input.userInfoEndpoint ?? discovered?.userInfoEndpoint;
        const jwksEndpoint = input.jwksEndpoint ?? discovered?.jwksEndpoint;

        const provider: SsoProvider = {
          id: crypto.randomUUID(),
          issuer: input.issuer,
          domain: normalizeDomain(input.domain),
          protocol: "oidc",
          clientId: input.clientId,
          clientSecret: input.clientSecret,
          redirectUri: input.redirectUri,
          authorizationEndpoint,
          tokenEndpoint,
          ...(userInfoEndpoint !== undefined && { userInfoEndpoint }),
          ...(jwksEndpoint !== undefined && { jwksEndpoint }),
          scopes: input.scopes ?? defaultScopes,
          usePKCE: input.usePKCE ?? true,
          ...(input.organizationId !== undefined && { organizationId: input.organizationId }),
          userId: registrarUserId,
          createdAt: Date.now(),
        };
        return yield* store.create(provider);
      }),

    resolveProviderForEmail: (email) =>
      Effect.gen(function* () {
        const store = yield* SsoProviderStore;
        return yield* store.getByDomain(domainOf(email));
      }),

    signIn: (selector) =>
      Effect.gen(function* () {
        const provider = yield* resolveProvider(selector);
        const oauth = makeOAuthProvider(
          stateProviderName(provider.id),
          toOAuthConfig(provider),
          provider.usePKCE,
        );
        const result = yield* oauth
          .generateAuthorizationUrl()
          .pipe(Effect.mapError((e) => new SsoError({ message: e.message, cause: e })));
        return { url: result.url, state: result.state };
      }),

    handleCallback: (state, code) =>
      Effect.gen(function* () {
        const stateStore = yield* OAuthStateStore;
        const userStore = yield* OAuthUserStore;
        const sessionManager = yield* SessionManager;
        const providerStore = yield* SsoProviderStore;

        const stateEntry = yield* stateStore
          .get(state)
          .pipe(Effect.mapError(() => new SsoError({ message: "SSO state not found or expired" })));
        if (stateEntry === null) {
          return yield* new SsoError({ message: "SSO state not found or expired" });
        }
        if (Date.now() > stateEntry.expiresAt) {
          yield* stateStore.delete(state);
          return yield* new SsoError({ message: "SSO state expired" });
        }

        const providerId = idFromStateProvider(stateEntry.provider);
        if (providerId === null) {
          return yield* new SsoError({ message: "State does not belong to an SSO sign-in" });
        }
        const provider = yield* providerStore.getById(providerId);
        if (provider === null) {
          return yield* new SsoError({ message: "SSO provider no longer exists" });
        }

        const oauth = makeOAuthProvider(
          stateProviderName(provider.id),
          toOAuthConfig(provider),
          provider.usePKCE,
        );
        const tokens = yield* oauth
          .exchangeCode(code, stateEntry.codeVerifier)
          .pipe(Effect.mapError((e) => new SsoError({ message: e.message, cause: e })));
        const profile = yield* oauth
          .getProfile(tokens, {
            ...(stateEntry.nonce !== undefined && { expectedNonce: stateEntry.nonce }),
          })
          .pipe(Effect.mapError((e) => new SsoError({ message: e.message, cause: e })));

        yield* stateStore.delete(state);

        if (profile.email === undefined || profile.email_verified === false) {
          return yield* new SsoError({
            message: "SSO provider did not return a verified email address",
          });
        }
        const email = profile.email.trim().toLowerCase();

        let user = yield* userStore.getUserByEmail(email);
        const isNewUser = user === null;
        if (user === null) {
          user = yield* userStore.createUser({
            email,
            emailVerified: true,
            ...(profile.name !== undefined && { name: profile.name }),
            ...(profile.picture !== undefined && { image: profile.picture }),
          });
        }

        // Provision organization membership on first login when configured.
        if (isNewUser && provider.organizationId !== undefined) {
          const orgStore = yield* Effect.serviceOption(OrganizationStore);
          if (orgStore._tag === "Some") {
            const existing = yield* orgStore.value.getMember(provider.organizationId, user.id);
            if (existing === null) {
              const member: Member = {
                id: crypto.randomUUID(),
                organizationId: provider.organizationId,
                userId: user.id,
                role: defaultRole,
                createdAt: Date.now(),
              };
              yield* orgStore.value.createMember(member);
            }
          }
        }

        const session = yield* sessionManager.createSession(user.id);
        return { user, session, isNewUser, provider };
      }),
  } satisfies SsoServiceShape);
};
