/**
 * Enterprise SSO (single sign-on) — OIDC and SAML 2.0 relying party with domain
 * routing.
 *
 * Lets tenants bring their own identity provider: register a per-organization
 * connection, route sign-ins by email domain, and provision users (and,
 * optionally, organization members) on first login. Both protocols converge on
 * the same provisioning tail — find-or-create by IdP-verified email, claim the
 * identifier as verified, optionally add the user to the connection's
 * organization, then mint a session.
 *
 * An **OIDC** connection is, under the hood, a dynamically-registered OAuth
 * provider, so that half reuses the machinery in {@link module:oauth} —
 * {@link OAuth.provider}, {@link discoverOAuthEndpoints}, and the shared
 * {@link OAuthStateStore}.
 *
 * A **SAML** connection stores the IdP's entity id, its HTTP-Redirect SSO
 * endpoint and its *pinned* signing certificates. Core owns the flow — minting
 * the `AuthnRequest` id, one-time-use enforcement, issuer checks, provisioning
 * — but not the XML: signature verification, canonicalisation and DEFLATE live
 * behind the {@link SAMLVerifier} contract in {@link module:saml}, implemented
 * by `@thomasfosterau/effect-auth-saml`. Both {@link SAMLVerifier} and
 * {@link SAMLReplayStore} are resolved *optionally*, so an app with no SAML
 * connections never installs an XML stack.
 *
 * @module sso
 */
import { Context, Crypto, Data, Effect, Layer, Redacted } from "effect";
import { AuthError } from "./Errors.ts";
import { claimIdentifier, IdentifierStore, makeIdentifier } from "./Identifier.ts";
import { UserStore } from "./UserStore.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { OrganizationStore, type Member } from "./Organization.ts";
import {
  defaultClockSkewMs,
  SAMLReplayStore,
  SAMLVerifier,
  type SAMLAssertion,
  type SAMLSignatureAlgorithm,
} from "./SAML.ts";
import {
  discoverOAuthEndpoints,
  OAuthStateStore,
  OAuthUserStore,
  type OAuthProviderConfig,
} from "./oauth/OAuth.ts";
import * as OAuth from "./oauth/OAuth.ts";
import type * as Types from "./Types.ts";

/** Failure to register, resolve, or complete an SSO sign-in. */
export class SSOError extends Data.TaggedError("SSOError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * A registered **OIDC** SSO connection. Endpoints may be supplied directly or
 * populated from the issuer's discovery document at registration time.
 *
 * This is one arm of the {@link SSOProvider} union discriminated on
 * `protocol`; {@link SAMLSSOProvider} is the other. Narrow before reaching for
 * protocol-specific fields.
 */
export interface OIDCSSOProvider {
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

/**
 * A registered **SAML 2.0** SSO connection: this SP's identity, the IdP's, and
 * the trust anchor between them.
 *
 * {@link idpCertificates} is the whole of that trust anchor — certificates
 * embedded in a response's `KeyInfo` are never consulted. Keeping it a list is
 * what makes IdP certificate rotation a no-downtime operation: add the new
 * certificate, wait out the overlap, drop the old one.
 */
export interface SAMLSSOProvider {
  readonly id: string;
  /** Email domain that routes to this provider (normalized, lowercase). */
  readonly domain: string;
  readonly protocol: "saml";
  /** The IdP's entity id — the `Issuer` every assertion must carry. */
  readonly entityId: string;
  /** The IdP's HTTP-Redirect binding single sign-on endpoint. */
  readonly ssoUrl: string;
  /** Pinned IdP signing certificates, PEM-encoded. At least one; more allow rotation. */
  readonly idpCertificates: ReadonlyArray<string>;
  /** This SP's entity id, asserted in `AudienceRestriction`. */
  readonly spEntityId: string;
  /** This SP's assertion consumer service URL, checked against `Destination`/`Recipient`. */
  readonly acsUrl: string;
  /** Minimum signature/digest strength to accept. Default: SHA-256 and stronger. */
  readonly signatureAlgorithms?: ReadonlyArray<SAMLSignatureAlgorithm>;
  /** Require the `Assertion` itself to be signed. Default `true`. */
  readonly wantAssertionsSigned?: boolean;
  /** Require the whole `Response` to be signed. Default `false`. */
  readonly wantAuthnResponseSigned?: boolean;
  /** Ask the IdP to re-authenticate on every sign-in. */
  readonly forceAuthn?: boolean;
  /** Organization to add the user to on first login (with the configured default role). */
  readonly organizationId?: string;
  /** User id of the admin who registered the connection. */
  readonly userId: string;
  /** Epoch milliseconds. */
  readonly createdAt: number;
}

/**
 * A registered SSO connection of **either** protocol — a discriminated union on
 * `protocol`.
 *
 * This is the type the store and the service speak in, and the one to reach for
 * when a value's protocol is not known statically; narrow on `protocol` to get
 * at {@link OIDCSSOProvider}- or {@link SAMLSSOProvider}-specific fields.
 */
export type SSOProvider = OIDCSSOProvider | SAMLSSOProvider;

/**
 * Persistent registry of SSO connections.
 *
 * The contract is protocol-agnostic: it stores whatever {@link SSOProvider}
 * arm it is handed, so adding SAML needed no new methods. Adapters that
 * serialize to columns should key off `protocol` when reading a row back.
 */
export class SSOProviderStore extends Context.Service<
  SSOProviderStore,
  {
    readonly create: (provider: SSOProvider) => Effect.Effect<SSOProvider, AuthError>;
    readonly getById: (id: string) => Effect.Effect<SSOProvider | null, AuthError>;
    readonly getByDomain: (domain: string) => Effect.Effect<SSOProvider | null, AuthError>;
    readonly list: () => Effect.Effect<ReadonlyArray<SSOProvider>, AuthError>;
  }
>()("@effect-auth/SSOProviderStore") {}

/** Input to {@link SSOService.registerProvider} (OIDC connections). */
export interface RegisterProviderInput {
  /** Present for symmetry with {@link RegisterSAMLProviderInput}; OIDC is the default. */
  readonly protocol?: "oidc";
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

/** Input to {@link SSOService.registerSAMLProvider}. */
export interface RegisterSAMLProviderInput {
  readonly protocol: "saml";
  readonly domain: string;
  /** The IdP's entity id (its `Issuer`). */
  readonly entityId: string;
  /** The IdP's HTTP-Redirect binding SSO endpoint. */
  readonly ssoUrl: string;
  /** Pinned IdP signing certificates, PEM-encoded. Must not be empty. */
  readonly idpCertificates: ReadonlyArray<string>;
  /** This SP's entity id. */
  readonly spEntityId: string;
  /** This SP's assertion consumer service URL. */
  readonly acsUrl: string;
  readonly signatureAlgorithms?: ReadonlyArray<SAMLSignatureAlgorithm>;
  readonly wantAssertionsSigned?: boolean;
  readonly wantAuthnResponseSigned?: boolean;
  readonly forceAuthn?: boolean;
  readonly organizationId?: string;
}

/** Result of a completed SSO sign-in. */
export interface SSOSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  readonly provider: SSOProvider;
}

/** Where to start an SSO sign-in from. */
export interface SSOSignInSelector {
  readonly email?: string;
  readonly providerId?: string;
  readonly domain?: string;
}

export class SSOService extends Context.Service<
  SSOService,
  {
    /**
     * Register (or discover + register) an SSO connection. The registrar
     * (`registrarUserId`) is recorded on the connection; gate this behind an
     * admin check at the HTTP layer.
     */
    readonly registerProvider: (
      registrarUserId: string,
      input: RegisterProviderInput,
    ) => Effect.Effect<OIDCSSOProvider, SSOError | AuthError>;

    /**
     * Register a SAML 2.0 connection. Kept separate from
     * {@link registerProvider} so each protocol keeps a precise input *and*
     * result type instead of forcing every caller to narrow a union.
     *
     * The registrar (`registrarUserId`) is recorded on the connection; gate
     * this behind an admin check at the HTTP layer.
     */
    readonly registerSAMLProvider: (
      registrarUserId: string,
      input: RegisterSAMLProviderInput,
    ) => Effect.Effect<SAMLSSOProvider, SSOError | AuthError>;

    /**
     * Resolve the connection an email address routes to, by domain. Returns
     * `null` when no connection matches.
     */
    readonly resolveProviderForEmail: (
      email: string,
    ) => Effect.Effect<SSOProvider | null, AuthError>;

    /**
     * Begin an SSO sign-in: resolve the connection (by `providerId`, `domain`,
     * or the domain of `email`) and return the URL to redirect the user to.
     *
     * For an OIDC connection that is the IdP's authorization URL and `state` is
     * the OAuth CSRF state. For a SAML connection it is the IdP's SSO endpoint
     * carrying a deflated `SAMLRequest`, and `state` is the `RelayState` the
     * IdP will echo back to the ACS endpoint — the same round-trip token in
     * both protocols, so callers need not branch.
     */
    readonly signIn: (
      selector: SSOSignInSelector,
    ) => Effect.Effect<
      { readonly url: string; readonly state: string },
      SSOError | AuthError,
      OAuthStateStore | Crypto.Crypto
    >;

    /**
     * Complete the OIDC SSO callback: exchange the code, verify the profile,
     * find-or-create the user by verified email, optionally add them to the
     * connection's organization, and issue a session.
     */
    readonly handleCallback: (
      state: string,
      code: string,
    ) => Effect.Effect<
      SSOSignInResult,
      SSOError | AuthError | HookError,
      OAuthStateStore | OAuthUserStore | IdentifierStore | UserStore | SessionService | Hooks
    >;

    /**
     * Complete the SAML assertion consumer service (ACS) POST: verify the
     * response against the connection's pinned certificates, spend the
     * `AuthnRequest` and the assertion id one time each, then run the same
     * provisioning tail as {@link handleCallback}.
     *
     * `samlResponse` is the `SAMLResponse` form field exactly as posted
     * (base64); `relayState` is the `RelayState` field when the IdP echoed one.
     */
    readonly handleSAMLCallback: (
      providerId: string,
      samlResponse: string,
      relayState?: string,
    ) => Effect.Effect<
      SSOSignInResult,
      SSOError | AuthError | HookError,
      OAuthUserStore | IdentifierStore | UserStore | SessionService | Hooks
    >;

    /**
     * Render the SP `EntityDescriptor` XML for a SAML connection, ready to hand
     * to the IdP's administrator (or serve from a metadata endpoint).
     */
    readonly samlMetadata: (providerId: string) => Effect.Effect<string, SSOError | AuthError>;
  }
>()("@effect-auth/SSOService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: SSOConfig = {}) =>
    Layer.effect(SSOService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/** Configuration for {@link make}. */
export interface SSOConfig {
  /** Default scopes when a connection doesn't specify any. */
  readonly defaultScopes?: readonly string[];
  /** Role granted when auto-adding a user to a connection's organization. */
  readonly defaultRole?: string;
  /**
   * How long a minted SAML `AuthnRequest` id stays spendable. Default 10
   * minutes — long enough for a password prompt and an MFA challenge, short
   * enough that abandoned requests do not accumulate.
   */
  readonly samlRequestTtl?: number;
  /**
   * Clock drift tolerated between the IdP and this SP when checking assertion
   * validity windows. Default {@link defaultClockSkewMs} (3 minutes).
   */
  readonly samlClockSkewMs?: number;
  /**
   * Fallback replay window for an assertion that carries no `NotOnOrAfter`.
   * Default 10 minutes. When the assertion does declare an expiry, that is used
   * instead — the id only needs to be remembered for as long as it is valid.
   */
  readonly samlAssertionReplayTtl?: number;
  /**
   * Accept assertions with no `InResponseTo` (IdP-initiated sign-on). Off by
   * default: an unsolicited response cannot be tied to a request this SP made,
   * which forfeits the login-CSRF protection `InResponseTo` provides.
   */
  readonly allowIdpInitiated?: boolean;
}

const normalizeDomain = (value: string): string => value.trim().toLowerCase();
const domainOf = (email: string): string => normalizeDomain(email.split("@")[1] ?? "");

/** The `sso:`-prefixed provider name stored in OAuth state, encoding the id. */
const stateProviderName = (id: string): string => `sso:${id}`;
const idFromStateProvider = (name: string): string | null =>
  name.startsWith("sso:") ? name.slice(4) : null;

/** Build the OAuth provider config for an SSO connection. */
const toOAuthConfig = (provider: OIDCSSOProvider): OAuthProviderConfig => ({
  clientId: provider.clientId,
  clientSecret: Redacted.make(provider.clientSecret),
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

export const make = (
  config: SSOConfig = {},
): Effect.Effect<typeof SSOService.Service, never, SSOProviderStore | Crypto.Crypto> =>
  Effect.gen(function* () {
    const defaultScopes = config.defaultScopes ?? ["openid", "email", "profile"];
    const defaultRole = config.defaultRole ?? "member";
    const samlRequestTtl = config.samlRequestTtl ?? 10 * 60 * 1000;
    const samlClockSkewMs = config.samlClockSkewMs ?? defaultClockSkewMs;
    const samlAssertionReplayTtl = config.samlAssertionReplayTtl ?? 10 * 60 * 1000;
    const allowIdpInitiated = config.allowIdpInitiated ?? false;

    const store = yield* SSOProviderStore;
    const crypto = yield* Crypto.Crypto;

    const randomId = (): Effect.Effect<string, AuthError> =>
      crypto.randomUUIDv4.pipe(
        Effect.mapError((cause) => new AuthError({ message: "Failed to generate id", cause })),
      );

    /**
     * SAML message ids are XML `NCName`s, which may not start with a digit —
     * hence the leading underscore. Dashes are dropped only for looks.
     */
    const randomMessageId = (): Effect.Effect<string, AuthError> =>
      Effect.map(randomId(), (id) => `_${id.replaceAll("-", "")}`);

    /**
     * The SAML pieces are resolved from ambient context rather than required by
     * this layer, so apps with no SAML connections never install an XML stack.
     * The cost is that "not installed" is a runtime error — but only on a code
     * path that a SAML connection had to be registered to reach.
     */
    const requireSAML = Effect.gen(function* () {
      const verifier = yield* Effect.serviceOption(SAMLVerifier);
      if (verifier._tag === "None") {
        return yield* new SSOError({
          message:
            "SAML support is not installed: provide the SAMLVerifier layer from @thomasfosterau/effect-auth-saml",
        });
      }
      const replay = yield* Effect.serviceOption(SAMLReplayStore);
      if (replay._tag === "None") {
        return yield* new SSOError({
          message: "SAML support is not installed: provide a SAMLReplayStore layer",
        });
      }
      return { verifier: verifier.value, replay: replay.value };
    });

    /** Resolve a connection by id, insisting it speaks SAML. */
    const requireSAMLProvider = (providerId: string) =>
      Effect.gen(function* () {
        const provider = yield* store.getById(providerId);
        if (provider === null) {
          return yield* new SSOError({ message: "SSO provider not found" });
        }
        if (provider.protocol !== "saml") {
          return yield* new SSOError({
            message: `SSO provider "${providerId}" is an OIDC connection, not a SAML one`,
          });
        }
        return provider;
      });

    /**
     * The tail both protocols share: find-or-create the user by an
     * IdP-verified email, promote the identifier to verified, provision org
     * membership on first login, then mint the session.
     *
     * Callers must have established that `profile.email` is verified *by the
     * IdP* — an OIDC `email_verified` claim, or an attribute inside a
     * signature-covered SAML assertion. Everything downstream treats it as
     * proof of control over the address.
     */
    const provisionAndSignIn = Effect.fn("SSOService.provisionAndSignIn")(function* (
      provider: SSOProvider,
      profile: { readonly email: string; readonly name?: string; readonly image?: string },
    ) {
      const userStore = yield* OAuthUserStore;
      const identifiers = yield* IdentifierStore;
      const users = yield* UserStore;
      const sessionManager = yield* SessionService;

      const email = profile.email.trim().toLowerCase();

      const identifier = yield* identifiers.getByValue("email", email);
      let user = identifier === null ? null : yield* users.get(identifier.userId);
      if (identifier !== null && user === null) {
        return yield* new SSOError({ message: "Account is unavailable" });
      }
      const isNewUser = user === null;
      if (user === null) {
        user = yield* userStore.createUser({
          ...(profile.name !== undefined && { name: profile.name }),
          ...(profile.image !== undefined && { image: profile.image }),
        });
        // The IdP attested the address as verified.
        yield* claimIdentifier(
          identifiers,
          makeIdentifier({
            userId: user.id,
            type: "email",
            value: email,
            verified: true,
            verifiedAt: new Date(),
          }),
        ).pipe(
          Effect.catchTag("IdentifierTakenError", () =>
            Effect.fail(new SSOError({ message: "This email is already in use" })),
          ),
        );
      } else if (identifier !== null && !identifier.verified) {
        yield* identifiers.setVerified(identifier.id, new Date());
      }

      // Provision organization membership on first login when configured.
      if (isNewUser && provider.organizationId !== undefined) {
        const orgStore = yield* Effect.serviceOption(OrganizationStore);
        if (orgStore._tag === "Some") {
          const existing = yield* orgStore.value.getMember(provider.organizationId, user.id);
          if (existing === null) {
            const member: Member = {
              id: yield* randomId(),
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
      return { user, session, isNewUser, provider } satisfies SSOSignInResult;
    });

    /**
     * The address to sign the user in as. Prefer an explicit email attribute;
     * fall back to the `NameID` only when the IdP labelled it as an email
     * address (or left the format unspecified and sent something that plainly
     * is one). Both sources sit inside the signature, so either is IdP-attested.
     */
    const emailFromAssertion = (assertion: SAMLAssertion): string | null => {
      if (assertion.email !== undefined && assertion.email.includes("@")) return assertion.email;
      const format = assertion.nameIdFormat;
      const looksLikeEmail = assertion.nameId.includes("@");
      const emailFormat =
        format === undefined ||
        format.endsWith(":emailAddress") ||
        format.endsWith(":nameid-format:unspecified");
      return looksLikeEmail && emailFormat ? assertion.nameId : null;
    };

    const resolveProvider = (selector: SSOSignInSelector) =>
      Effect.gen(function* () {
        if (selector.providerId !== undefined) {
          const p = yield* store.getById(selector.providerId);
          if (p === null) {
            return yield* new SSOError({ message: "SSO provider not found" });
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
          return yield* new SSOError({ message: "An email, domain, or providerId is required" });
        }
        const p = yield* store.getByDomain(domain);
        if (p === null) {
          return yield* new SSOError({ message: `No SSO provider for domain "${domain}"` });
        }
        return p;
      });

    return {
      registerProvider: Effect.fn("SSOService.registerProvider")(function* (
        registrarUserId: string,
        input: RegisterProviderInput,
      ) {
        const discovered = input.discover
          ? yield* discoverOAuthEndpoints(input.issuer).pipe(
              Effect.mapError((e) => new SSOError({ message: e.message, cause: e })),
            )
          : undefined;

        const authorizationEndpoint =
          input.authorizationEndpoint ?? discovered?.authorizationEndpoint;
        const tokenEndpoint = input.tokenEndpoint ?? discovered?.tokenEndpoint;
        if (authorizationEndpoint === undefined || tokenEndpoint === undefined) {
          return yield* new SSOError({
            message:
              "authorizationEndpoint and tokenEndpoint are required (set `discover: true` or pass them explicitly)",
          });
        }
        const userInfoEndpoint = input.userInfoEndpoint ?? discovered?.userInfoEndpoint;
        const jwksEndpoint = input.jwksEndpoint ?? discovered?.jwksEndpoint;

        const provider: OIDCSSOProvider = {
          id: yield* randomId(),
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
        // The store speaks the `SSOProvider` union; narrow the record it
        // hands back to the arm we asked it to persist.
        const created = yield* store.create(provider);
        if (created.protocol !== "oidc") {
          return yield* new SSOError({
            message: "SSO provider store returned a record for the wrong protocol",
          });
        }
        return created;
      }),

      registerSAMLProvider: Effect.fn("SSOService.registerSAMLProvider")(function* (
        registrarUserId: string,
        input: RegisterSAMLProviderInput,
      ) {
        if (input.idpCertificates.length === 0) {
          return yield* new SSOError({
            message:
              "idpCertificates must not be empty: the IdP's signing certificate is the only trust anchor for a SAML connection",
          });
        }
        for (const [label, value] of [
          ["ssoUrl", input.ssoUrl],
          ["acsUrl", input.acsUrl],
        ] as const) {
          if (!URL.canParse(value)) {
            return yield* new SSOError({ message: `${label} must be an absolute URL` });
          }
        }
        if (input.entityId.trim() === "" || input.spEntityId.trim() === "") {
          return yield* new SSOError({ message: "entityId and spEntityId are required" });
        }

        const provider: SAMLSSOProvider = {
          id: yield* randomId(),
          domain: normalizeDomain(input.domain),
          protocol: "saml",
          entityId: input.entityId,
          ssoUrl: input.ssoUrl,
          idpCertificates: input.idpCertificates,
          spEntityId: input.spEntityId,
          acsUrl: input.acsUrl,
          ...(input.signatureAlgorithms !== undefined && {
            signatureAlgorithms: input.signatureAlgorithms,
          }),
          ...(input.wantAssertionsSigned !== undefined && {
            wantAssertionsSigned: input.wantAssertionsSigned,
          }),
          ...(input.wantAuthnResponseSigned !== undefined && {
            wantAuthnResponseSigned: input.wantAuthnResponseSigned,
          }),
          ...(input.forceAuthn !== undefined && { forceAuthn: input.forceAuthn }),
          ...(input.organizationId !== undefined && { organizationId: input.organizationId }),
          userId: registrarUserId,
          createdAt: Date.now(),
        };
        const created = yield* store.create(provider);
        if (created.protocol !== "saml") {
          return yield* new SSOError({
            message: "SSO provider store returned a record for the wrong protocol",
          });
        }
        return created;
      }),

      resolveProviderForEmail: Effect.fn("SSOService.resolveProviderForEmail")(function* (
        email: string,
      ) {
        return yield* store.getByDomain(domainOf(email));
      }),

      signIn: Effect.fn("SSOService.signIn")(function* (selector: SSOSignInSelector) {
        const provider = yield* resolveProvider(selector);

        if (provider.protocol === "saml") {
          const { verifier, replay } = yield* requireSAML;
          const relayState = yield* randomId();
          const requestId = yield* randomMessageId();
          const request = yield* verifier
            .buildAuthnRequest({
              ssoUrl: provider.ssoUrl,
              spEntityId: provider.spEntityId,
              acsUrl: provider.acsUrl,
              requestId,
              relayState,
              ...(provider.forceAuthn !== undefined && { forceAuthn: provider.forceAuthn }),
            })
            .pipe(Effect.mapError((e) => new SSOError({ message: e.message, cause: e })));

          // Record the request id *before* redirecting: the response can only
          // be accepted if it answers a request we know we made, and spending
          // that record is what makes the round trip one-time-use.
          const now = Date.now();
          const created = yield* replay.create({
            id: request.requestId,
            kind: "authn-request",
            providerId: provider.id,
            relayState,
            createdAt: now,
            expiresAt: now + samlRequestTtl,
          });
          if (created === null) {
            return yield* new SSOError({ message: "Failed to record the SAML request id" });
          }
          return { url: request.url, state: relayState };
        }

        const oauth = OAuth.provider(
          stateProviderName(provider.id),
          toOAuthConfig(provider),
          provider.usePKCE,
        );
        const result = yield* oauth
          .generateAuthorizationUrl()
          .pipe(Effect.mapError((e) => new SSOError({ message: e.message, cause: e })));
        return { url: result.url, state: result.state };
      }),

      handleCallback: Effect.fn("SSOService.handleCallback")(function* (
        state: string,
        code: string,
      ) {
        const stateStore = yield* OAuthStateStore;

        const stateEntry = yield* stateStore
          .get(state)
          .pipe(Effect.mapError(() => new SSOError({ message: "SSO state not found or expired" })));
        if (stateEntry === null) {
          return yield* new SSOError({ message: "SSO state not found or expired" });
        }
        if (Date.now() > stateEntry.expiresAt) {
          yield* stateStore.delete(state);
          return yield* new SSOError({ message: "SSO state expired" });
        }

        const providerId = idFromStateProvider(stateEntry.provider);
        if (providerId === null) {
          return yield* new SSOError({ message: "State does not belong to an SSO sign-in" });
        }
        const provider = yield* store.getById(providerId);
        if (provider === null) {
          return yield* new SSOError({ message: "SSO provider no longer exists" });
        }
        if (provider.protocol !== "oidc") {
          return yield* new SSOError({
            message: "SSO state belongs to a SAML connection; use handleSAMLCallback",
          });
        }

        const oauth = OAuth.provider(
          stateProviderName(provider.id),
          toOAuthConfig(provider),
          provider.usePKCE,
        );
        const tokens = yield* oauth
          .exchangeCode(code, stateEntry.codeVerifier)
          .pipe(Effect.mapError((e) => new SSOError({ message: e.message, cause: e })));
        const profile = yield* oauth
          .getProfile(tokens, {
            ...(stateEntry.nonce !== undefined && { expectedNonce: stateEntry.nonce }),
          })
          .pipe(Effect.mapError((e) => new SSOError({ message: e.message, cause: e })));

        yield* stateStore.delete(state);

        if (profile.email === undefined || profile.email_verified === false) {
          return yield* new SSOError({
            message: "SSO provider did not return a verified email address",
          });
        }

        return yield* provisionAndSignIn(provider, {
          email: profile.email,
          ...(profile.name !== undefined && { name: profile.name }),
          ...(profile.picture !== undefined && { image: profile.picture }),
        });
      }),

      handleSAMLCallback: Effect.fn("SSOService.handleSAMLCallback")(function* (
        providerId: string,
        samlResponse: string,
        relayState?: string,
      ) {
        const provider = yield* requireSAMLProvider(providerId);
        const { verifier, replay } = yield* requireSAML;

        // The verifier owns the XML/crypto checklist (signature over pinned
        // certificates, single assertion, audience, Destination/Recipient,
        // validity window, algorithm allow-list). Everything below is the
        // flow-level half that only this service can enforce.
        const assertion = yield* verifier
          .verify({
            samlResponse,
            ...(relayState !== undefined && { relayState }),
            idpCertificates: provider.idpCertificates,
            idpEntityId: provider.entityId,
            spEntityId: provider.spEntityId,
            acsUrl: provider.acsUrl,
            clockSkewMs: samlClockSkewMs,
            ...(provider.signatureAlgorithms !== undefined && {
              allowedSignatureAlgorithms: provider.signatureAlgorithms,
            }),
            ...(provider.wantAssertionsSigned !== undefined && {
              wantAssertionsSigned: provider.wantAssertionsSigned,
            }),
            ...(provider.wantAuthnResponseSigned !== undefined && {
              wantAuthnResponseSigned: provider.wantAuthnResponseSigned,
            }),
          })
          .pipe(Effect.mapError((e) => new SSOError({ message: e.message, cause: e })));

        // Defence in depth: the verifier already pins the issuer, but this
        // service is the one that knows which connection was addressed.
        if (assertion.issuer !== provider.entityId) {
          return yield* new SSOError({
            message: `SAML assertion issuer "${assertion.issuer}" does not match this connection`,
          });
        }

        // Spend the AuthnRequest. Verification runs first because the request
        // id is inside the response we have yet to trust; consuming it here —
        // after the signature holds — is what makes the round trip one-shot.
        if (assertion.inResponseTo === undefined) {
          if (!allowIdpInitiated) {
            return yield* new SSOError({
              message: "SAML response has no InResponseTo (IdP-initiated sign-on is not enabled)",
            });
          }
        } else {
          const pending = yield* replay.consume(assertion.inResponseTo);
          if (pending === null || pending.kind !== "authn-request") {
            return yield* new SSOError({
              message: "SAML response answers an unknown, expired, or already-used request",
            });
          }
          if (pending.providerId !== provider.id) {
            return yield* new SSOError({
              message: "SAML response answers a request issued for a different connection",
            });
          }
          if (pending.relayState !== undefined && pending.relayState !== relayState) {
            return yield* new SSOError({ message: "SAML RelayState does not match the request" });
          }
        }

        // Spend the assertion id itself, so a captured response cannot be
        // replayed inside its own validity window (or at all, for an
        // IdP-initiated one, where there is no request to spend).
        const now = Date.now();
        const seen = yield* replay.create({
          id: assertion.id,
          kind: "assertion",
          providerId: provider.id,
          createdAt: now,
          expiresAt: assertion.notOnOrAfter ?? now + samlAssertionReplayTtl,
        });
        if (seen === null) {
          return yield* new SSOError({ message: "SAML assertion has already been used" });
        }

        const email = emailFromAssertion(assertion);
        if (email === null) {
          return yield* new SSOError({
            message: "SAML assertion did not carry an email address",
          });
        }

        return yield* provisionAndSignIn(provider, {
          email,
          ...(assertion.displayName !== undefined && { name: assertion.displayName }),
        });
      }),

      samlMetadata: Effect.fn("SSOService.samlMetadata")(function* (providerId: string) {
        const provider = yield* requireSAMLProvider(providerId);
        const { verifier } = yield* requireSAML;
        return yield* verifier
          .spMetadataXml({
            spEntityId: provider.spEntityId,
            acsUrl: provider.acsUrl,
            wantAssertionsSigned: provider.wantAssertionsSigned ?? true,
          })
          .pipe(Effect.mapError((e) => new SSOError({ message: e.message, cause: e })));
      }),
    } satisfies typeof SSOService.Service;
  });
