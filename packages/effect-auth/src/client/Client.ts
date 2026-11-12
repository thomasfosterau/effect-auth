/**
 * Vanilla auth client for the effect-auth HTTP protocol.
 *
 * A small, dependency-free client (plain `fetch`, no Effect runtime in the
 * bundle) with methods mirroring the contract's endpoint names. The client
 * holds no session state: it announces each session-changing call to its
 * observers (`onSessionChange`), and the session itself is an
 * `effect/reactivity` Atom graph over the client in the `./client/atoms`
 * subpath (`SessionAtoms.ts`), which the Svelte binding
 * (`@thomasfosterau/effect-auth-svelte`) adapts.
 *
 * Only the wire *types* are imported from the `http/` tier — they erase at
 * compile time, so the browser bundle contains just this file.
 *
 * @module client
 */
import type * as Http from "../http/index.ts";

/** A non-2xx response from the auth server. */
export class AuthClientError extends Error {
  override readonly name = "AuthClientError";
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * A pending second-factor challenge could not be continued: either the
 * authentication result carried none (`reason: "missing"`), or the challenge
 * has expired client-side before the code was submitted (`reason: "expired"`).
 *
 * The expiry check is a local courtesy — the server enforces expiry too — so a
 * UI can tell the user to sign in again without spending a round trip.
 */
export class SecondFactorChallengeError extends Error {
  override readonly name = "SecondFactorChallengeError";
  readonly reason: "missing" | "expired";

  constructor(reason: "missing" | "expired", message: string) {
    super(message);
    this.reason = reason;
  }
}

/**
 * What a sign-in, sign-up or email verification resolves with.
 *
 * `user` is present when the call issued a session. Without one, either
 * `secondFactor` is the challenge to redeem (see
 * {@link AuthClient.multiFactor}'s `continueChallenge`), or
 * `needsEmailVerification` is `true` and the address must be verified first. A
 * sign-up under the server's `antiEnumeration` mode always resolves without a
 * `user`, for a fresh address and a held one alike.
 */
export interface AuthResult {
  readonly user?: Http.UserView;
  readonly needsEmailVerification: boolean;
  readonly secondFactor?: Http.SecondFactorChallengeView;
}

/**
 * A pending second-factor challenge with the verify calls pre-bound to its
 * token. Obtained from {@link AuthClient.multiFactor}'s `continueChallenge`.
 */
export interface SecondFactorContinuation {
  /** The challenge token carried by `AuthResult.secondFactor`. */
  readonly token: string;
  /** Challenge expiry, epoch millis. */
  readonly expiresAt: number;
  /** `true` once {@link expiresAt} has passed on this device's clock. */
  readonly isExpired: () => boolean;
  /**
   * Redeem the challenge with a TOTP code. Rejects with a
   * {@link SecondFactorChallengeError} (`reason: "expired"`) without issuing a
   * request when the challenge has already expired.
   */
  readonly verifyTotp: (code: string) => Promise<AuthResult>;
  /** Redeem the challenge with a single-use backup code. */
  readonly verifyBackupCode: (code: string) => Promise<AuthResult>;
}

/**
 * An observer of session-changing calls, registered with
 * `AuthClient.onSessionChange`. A returned promise is awaited: the call that
 * changed the session resolves only once every observer has settled
 * (refetched, typically), so `await client.signIn(...)` is followed by an
 * up-to-date session. A rejection is ignored; it never fails the call.
 */
export type SessionChangeListener = () => void | Promise<void>;

/** Options for {@link createAuthClient}: the base URL, a `fetch` override and extra headers. */
export interface AuthClientOptions {
  /**
   * Base URL the auth handler is mounted at, e.g.
   * `"https://app.example.com/api/auth"` or `"/api/auth"` (same origin).
   */
  readonly baseUrl: string;
  /** Custom `fetch` (tests, SSR, mounting the handler in-process). */
  readonly fetch?: typeof globalThis.fetch | undefined;
  /** Extra headers attached to every request. */
  readonly headers?: Record<string, string> | undefined;
}

/** Internals exposed to plugins during {@link AuthClientPlugin.install}. */
export interface AuthClientPluginContext {
  /** Issue a raw HTTP request to the auth server. */
  readonly request: <T>(method: string, path: string, body?: unknown) => Promise<T>;
  /**
   * Issue a session-changing request, then notify the session observers
   * (`AuthClient.onSessionChange`) and wait for them to settle.
   */
  readonly mutating: <T>(run: () => Promise<T>) => Promise<T>;
}

/**
 * A plugin that adds typed methods to an auth client.
 *
 * ```ts skip-type-checking
 * const myPlugin = definePlugin((ctx) => ({
 *   myMethod: () => ctx.request<MyView>("GET", "/my-endpoint"),
 * }));
 * const client = createAuthClient({ baseUrl: "/api/auth" }).extend(myPlugin);
 * await client.myMethod();
 * ```
 */
export interface AuthClientPlugin<TExtension extends object> {
  readonly install: (context: AuthClientPluginContext) => TExtension;
}

/**
 * Create a strongly-typed plugin from an install function.
 *
 * @example
 * ```ts
 * import { definePlugin } from "@thomasfosterau/effect-auth/client";
 *
 * const reportPlugin = definePlugin((ctx) => ({
 *   fileReport: (title: string) =>
 *     ctx.request("POST", "/reports", { title }),
 * }));
 * ```
 */
export const definePlugin = <TExtension extends object>(
  install: (context: AuthClientPluginContext) => TExtension,
): AuthClientPlugin<TExtension> => ({ install });

/**
 * `true` when the response carries a JSON body.
 *
 * Compares the *essence* of `content-type` — the media type with its
 * parameters (`; charset=utf-8`) stripped — against `application/json` and
 * against the structured `+json` suffix (`application/problem+json`,
 * `application/vnd.example+json`, ...). A substring test would wrongly accept
 * `text/plain; note=application/json` and reject `application/problem+json`.
 */
const isJson = (response: Response): boolean => {
  const [mediaType = ""] = (response.headers.get("content-type") ?? "").split(";");
  const essence = mediaType.trim().toLowerCase();
  return essence === "application/json" || essence.endsWith("+json");
};

// --- JSON:API wire shapes ------------------------------------------------------
//
// The resource groups (`sessions`, `identifiers`, `users`) answer JSON:API
// documents (#205). The client keeps its view types and maps the documents onto
// them here, so callers see the same shapes as before.

const JSON_API = "application/vnd.api+json";

interface ResourceLinkage {
  readonly type: string;
  readonly id: string;
}

interface WireResource<A> {
  readonly type: string;
  readonly id: string;
  readonly attributes: A;
  readonly relationships?: {
    // `null` is an optional to-one relationship that links to nothing.
    readonly [name: string]: { readonly data: ResourceLinkage | null } | undefined;
  };
}

interface WireUser {
  readonly name?: string;
  readonly image?: string;
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly attributes: Http.Attributes;
}

interface WireSession {
  readonly expiresAt: number;
  readonly createdAt: number;
  readonly lastActivityAt: number;
  readonly attributes: Http.Attributes;
}

interface WireIdentifier {
  readonly kind: Http.IdentifierView["type"];
  readonly value: string;
  readonly verified: boolean;
  readonly verifiedAt?: number;
  readonly createdAt: number;
}

interface WireDeviceSession extends WireSession {
  readonly active: boolean;
}

type WireOrganization = Omit<Http.OrganizationView, "id">;

type WireMember = Omit<Http.MemberView, "id" | "organizationId" | "userId">;

type WireInvitation = Omit<Http.InvitationView, "id" | "organizationId" | "inviterId">;

/** A claim's attributes: its `attestedBy` travels as the `attester` relationship. */
type WireDomain = Omit<Http.OrganizationDomainView, "id" | "organizationId" | "attestedBy">;

type WireOrgRole = Omit<Http.OrgRoleView, "id" | "organizationId">;

type WireTeam = Omit<Http.TeamView, "id" | "organizationId">;

type WireTeamMember = Omit<Http.TeamMemberView, "id" | "teamId" | "userId">;

type WireApiKey = Omit<Http.ApiKeyView, "id" | "userId">;

/** An OIDC client's attributes: JSON:API reserves `type`, so it travels as `clientType`. */
type WireOAuthClient = Omit<Http.OidcClientView, "clientId" | "type"> & {
  readonly clientType: Http.OidcClientView["type"];
};

/** `Omit` over each member of a union, so a discriminated union stays one. */
type OmitEach<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

type WireSsoProvider = OmitEach<Http.SsoProviderView, "id" | "organizationId">;

interface DataDocument<A> {
  readonly data: WireResource<A>;
  readonly included?: ReadonlyArray<WireResource<WireUser>>;
}

/** What `PATCH /invitations/:id` answers; an acceptance carries the new membership in `meta`. */
interface InvitationTransitionDocument extends DataDocument<WireInvitation> {
  readonly meta?: { readonly membership?: WireResource<WireMember> };
}

interface CollectionDocument<A> {
  readonly data: ReadonlyArray<WireResource<A>>;
  readonly included?: ReadonlyArray<WireResource<WireUser>>;
}

/**
 * What `POST /sessions`, `POST /users` and the verifications answer: `201`
 * with the session (its user included), or `202` with a second-factor
 * challenge or no primary data. Sessions and challenges both carry
 * `expiresAt`.
 */
interface SignInDocument {
  readonly data?: WireResource<{ readonly expiresAt: number }>;
  readonly included?: ReadonlyArray<WireResource<WireUser>>;
  readonly meta?: { readonly needsEmailVerification?: boolean };
}

const userView = (resource: WireResource<WireUser>): Http.UserView => ({
  id: resource.id,
  ...resource.attributes,
});

const sessionView = (resource: WireResource<WireSession>): Http.SessionView => ({
  id: resource.id,
  userId: resource.relationships?.user?.data?.id ?? "",
  ...resource.attributes,
});

/** The id a resource's to-one relationship `name` links to (`""` when absent). */
const related = (resource: WireResource<unknown>, name: string): string =>
  resource.relationships?.[name]?.data?.id ?? "";

const organizationView = ({
  id,
  attributes,
}: WireResource<WireOrganization>): Http.OrganizationView => ({
  id,
  ...attributes,
});

const memberView = (resource: WireResource<WireMember>): Http.MemberView => ({
  id: resource.id,
  organizationId: related(resource, "organization"),
  userId: related(resource, "user"),
  ...resource.attributes,
});

const invitationView = (resource: WireResource<WireInvitation>): Http.InvitationView => ({
  id: resource.id,
  organizationId: related(resource, "organization"),
  inviterId: related(resource, "inviter"),
  ...resource.attributes,
});

/** A resource that belongs to one organization, with its `organizationId` back in place. */
const organizationOwned = <A>(
  resource: WireResource<A>,
): A & { readonly id: string; readonly organizationId: string } => ({
  id: resource.id,
  organizationId: related(resource, "organization"),
  ...resource.attributes,
});

/** A domain claim, its `attester` relationship (when it links anyone) as `attestedBy`. */
const domainView = (resource: WireResource<WireDomain>): Http.OrganizationDomainView => {
  const attestedBy = resource.relationships?.["attester"]?.data?.id;
  return {
    ...organizationOwned(resource),
    ...(attestedBy !== undefined && { attestedBy }),
  };
};

const teamMemberView = (resource: WireResource<WireTeamMember>): Http.TeamMemberView => ({
  id: resource.id,
  teamId: related(resource, "team"),
  userId: related(resource, "user"),
  ...resource.attributes,
});

/** The user `userId` names, from a document's `included` (an error when it is missing). */
const includedUser = (document: DataDocument<unknown>, userId: string): Http.UserView => {
  const user = document.included?.find((resource) => resource.id === userId);
  if (user === undefined) {
    throw new AuthClientError(0, `The ${document.data.type} document did not include its user`);
  }
  return userView(user);
};

/** The `admin-users` item path of user `userId`. */
const adminUserPath = (userId: string): string => `/admin/users/${encodeURIComponent(userId)}`;

/** A to-one relationship naming user `userId`. */
const userLinkage = (userId: string) => ({ data: { type: "users", id: userId } });

const apiKeyView = (resource: WireResource<WireApiKey>): Http.ApiKeyView => ({
  id: resource.id,
  userId: related(resource, "user"),
  ...resource.attributes,
});

const oauthClientView = ({
  id,
  attributes,
}: WireResource<WireOAuthClient>): Http.OidcClientView => {
  const { clientType, ...rest } = attributes;
  return { clientId: id, type: clientType, ...rest };
};

const ssoProviderView = (resource: WireResource<WireSsoProvider>): Http.SsoProviderView => {
  const organizationId = resource.relationships?.["organization"]?.data?.id;
  return {
    id: resource.id,
    ...resource.attributes,
    ...(organizationId !== undefined && { organizationId }),
  };
};

/** A `device-sessions` resource with its included user, as the session-with-user view. */
const deviceSessionView = (
  resource: WireResource<WireDeviceSession>,
  users: ReadonlyArray<WireResource<WireUser>>,
): ReadonlyArray<Http.SessionWithUserView> => {
  const { active: _active, ...attributes } = resource.attributes;
  const userId = related(resource, "user");
  const user = users.find((candidate) => candidate.id === userId);
  return user === undefined
    ? []
    : [{ session: { id: resource.id, userId, ...attributes }, user: userView(user) }];
};

const identifierView = ({ id, attributes }: WireResource<WireIdentifier>): Http.IdentifierView => {
  const { kind, ...rest } = attributes;
  return { id, type: kind, ...rest };
};

/** The {@link AuthResult} of a sign-in answer (`undefined` for a bodiless `204` / `202`). */
const authResult = (document: SignInDocument | undefined): AuthResult => {
  const needsEmailVerification = document?.meta?.needsEmailVerification ?? false;
  const data = document?.data;
  if (data === undefined) return { needsEmailVerification };
  if (data.type === "second-factor-challenges") {
    return {
      needsEmailVerification,
      secondFactor: { token: data.id, expiresAt: data.attributes.expiresAt },
    };
  }
  const user = document?.included?.find((resource) => resource.type === "users");
  return { ...(user !== undefined && { user: userView(user) }), needsEmailVerification };
};

/** The message of an error body: a JSON:API error document's first `detail`, or `{ message }`. */
const errorMessage = (body: unknown): string | undefined => {
  if (typeof body !== "object" || body === null) return undefined;
  if ("errors" in body && Array.isArray(body.errors)) {
    const first: unknown = body.errors[0];
    return typeof first === "object" &&
      first !== null &&
      "detail" in first &&
      typeof first.detail === "string"
      ? first.detail
      : undefined;
  }
  return "message" in body && typeof body.message === "string" ? body.message : undefined;
};

/** The auth client: typed methods over the contract, plus session-change notification. */
export interface AuthClient {
  /**
   * Observe session-changing calls (sign-in / up / out, second-factor
   * redemption, impersonation, switching the active organization, ...).
   * `listener` runs after each such call succeeds, and the call resolves only
   * once the listener's promise settles. Returns the function that removes it.
   *
   * The client keeps no session state of its own: the session Atoms in
   * `@thomasfosterau/effect-auth/client/atoms` register here while they are
   * observed and refetch on each notification, so a call nobody observes
   * costs no session round trip.
   */
  readonly onSessionChange: (listener: SessionChangeListener) => () => void;
  /**
   * Notify the session observers as a session-changing call would, and wait
   * for them to settle: the refetch for a change this client did not make
   * (a sign-out on the server, a form posted outside it).
   */
  readonly invalidateSession: () => Promise<void>;

  readonly signUp: (payload: Http.SignUpPayload) => Promise<AuthResult>;
  readonly signIn: (payload: Http.SignInPayload) => Promise<AuthResult>;
  readonly signOut: () => Promise<void>;
  /** Guest sign-in — creates an anonymous user + session. 404 when unconfigured. */
  readonly signInAnonymous: () => Promise<AuthResult>;
  /** Username + password sign-in. 404 when unconfigured. */
  readonly signInUsername: (payload: Http.UsernameSignInPayload) => Promise<AuthResult>;
  /** Resolves `null` when not authenticated (401). */
  readonly getSession: () => Promise<Http.SessionWithUserView | null>;
  readonly sendVerificationEmail: (payload: { email: string }) => Promise<Http.StatusResponse>;
  readonly verifyEmail: (payload: { token: string }) => Promise<AuthResult>;
  readonly passwordResetRequest: (payload: { email: string }) => Promise<Http.StatusResponse>;
  readonly passwordResetConfirm: (payload: {
    token: string;
    newPassword: string;
  }) => Promise<Http.StatusResponse>;
  readonly changePassword: (payload: Http.ChangePasswordPayload) => Promise<void>;
  readonly updateUser: (payload: Http.UpdateUserPayload) => Promise<Http.UserView>;
  readonly listSessions: () => Promise<readonly Http.SessionView[]>;
  readonly revokeSession: (sessionId: string) => Promise<void>;
  readonly revokeOtherSessions: () => Promise<void>;
  /** Fetch a signed JWT for the current session. 404 when unconfigured. */
  readonly jwtToken: () => Promise<Http.JwtTokenView>;
  /** The JWKS that verifies {@link jwtToken}'s tokens. 404 when unconfigured. */
  readonly jwks: () => Promise<Http.JwksView>;

  /**
   * The signed-in user's login handles (email / username / phone). The server
   * refuses to delete the last one (400) so an account is never orphaned.
   */
  readonly identifiers: {
    readonly list: () => Promise<Http.IdentifierListView>;
    readonly delete: (identifierId: string) => Promise<void>;
  };

  /** Verification-gated email change. 404 when unconfigured. */
  readonly changeEmail: {
    readonly request: (payload: Http.ChangeEmailRequestPayload) => Promise<Http.StatusResponse>;
    readonly confirm: (payload: Http.ChangeEmailConfirmPayload) => Promise<Http.StatusResponse>;
  };

  /** Self-service account deletion. 404 when unconfigured. */
  readonly deleteUser: {
    readonly request: () => Promise<Http.StatusResponse>;
    readonly confirm: (payload: Http.DeleteUserConfirmPayload) => Promise<Http.StatusResponse>;
  };

  /**
   * Multi-account management (several accounts per device), over
   * `/device-sessions`. 404 when unconfigured. Each listed session's `id` is
   * its stored id (the hash of its token, never the token), and `setActive` /
   * `revoke` take that id.
   */
  readonly multiSession: {
    readonly list: () => Promise<Http.MultiSessionListView>;
    readonly setActive: (payload: Http.MultiSessionActionPayload) => Promise<Http.StatusResponse>;
    readonly revoke: (payload: Http.MultiSessionActionPayload) => Promise<Http.StatusResponse>;
  };

  readonly magicLink: {
    readonly send: (payload: { email: string }) => Promise<Http.StatusResponse>;
    readonly verify: (payload: { token: string }) => Promise<AuthResult>;
  };

  readonly emailOtp: {
    readonly send: (payload: {
      email: string;
      purpose: Http.EmailOtpPurpose;
    }) => Promise<Http.StatusResponse>;
    readonly signIn: (payload: { email: string; otp: string }) => Promise<AuthResult>;
  };

  /** SMS one-time passcodes. 404 when unconfigured. */
  readonly phoneOtp: {
    readonly send: (payload: {
      phoneNumber: string;
      purpose: Http.PhoneOtpPurpose;
    }) => Promise<Http.StatusResponse>;
    readonly signIn: (payload: { phoneNumber: string; otp: string }) => Promise<AuthResult>;
  };

  /** Google One Tap. 404 when unconfigured. */
  readonly googleOneTap: {
    /** Server-generated nonce to hand to Google's One Tap prompt. */
    readonly nonce: () => Promise<Http.GoogleOneTapNonceView>;
    readonly signIn: (payload: Http.GoogleOneTapPayload) => Promise<AuthResult>;
  };

  /**
   * Device authorization grant (RFC 8628). `code`/`token` are called by the
   * input-constrained device; `approve`/`deny` by the signed-in user on the
   * verification page. 404 when unconfigured.
   */
  readonly device: {
    readonly code: (payload?: Http.DeviceCodePayload) => Promise<Http.DeviceCodeView>;
    /** Poll for the session. 400 while the user has not decided yet. */
    readonly token: (payload: Http.DeviceTokenPayload) => Promise<Http.AuthSuccess>;
    readonly approve: (payload: Http.DeviceUserCodePayload) => Promise<Http.StatusResponse>;
    readonly deny: (payload: Http.DeviceUserCodePayload) => Promise<Http.StatusResponse>;
  };

  readonly multiFactor: {
    readonly enable: (payload: { password: string }) => Promise<Http.MultiFactorEnableView>;
    readonly confirm: (payload: { code: string }) => Promise<Http.StatusResponse>;
    readonly disable: (payload: { password: string }) => Promise<Http.StatusResponse>;
    readonly regenerateBackupCodes: (payload: {
      password: string;
    }) => Promise<Http.BackupCodesView>;
    readonly verifyTotp: (payload: { token: string; code: string }) => Promise<AuthResult>;
    readonly verifyBackupCode: (payload: { token: string; code: string }) => Promise<AuthResult>;
    /**
     * Bind a pending challenge so the caller only needs to pass the code.
     *
     * ```ts skip-type-checking
     * const result = await client.signIn({ email, password });
     * if (result.secondFactor) {
     *   await client.multiFactor.challenge(result.secondFactor).verifyTotp(code);
     * }
     * ```
     */
    readonly challenge: (challenge: Http.SecondFactorChallengeView) => SecondFactorContinuation;
    /**
     * Carry a gated sign-in straight into the second-factor step: takes the
     * `AuthResult` a sign-in returned and hands back the verify calls bound
     * to its challenge.
     *
     * ```ts skip-type-checking
     * const result = await client.signIn({ email, password });
     * if (result.secondFactor) {
     *   const challenge = client.multiFactor.continueChallenge(result);
     *   await challenge.verifyTotp(codeFromUser); // session issued
     * }
     * ```
     *
     * Throws a {@link SecondFactorChallengeError} with `reason: "missing"`
     * when the result carries no challenge (the user is already signed in),
     * and the verify calls reject with `reason: "expired"` once the challenge
     * window has passed.
     */
    readonly continueChallenge: (result: AuthResult) => SecondFactorContinuation;
  };

  /**
   * Organizations: orgs, members (including deactivation), invitations,
   * claimed email domains, teams and per-organization roles. Every call is
   * session-authenticated; 404 when the module is absent and 403 when the
   * actor's role lacks the required permission.
   */
  readonly organization: {
    readonly create: (payload: Http.CreateOrganizationPayload) => Promise<Http.OrganizationView>;
    /** Organizations the signed-in user is a member of. */
    readonly list: () => Promise<Http.OrganizationListView>;
    /** One organization together with its members. */
    readonly get: (organizationId: string) => Promise<Http.FullOrganizationView>;
    readonly update: (
      organizationId: string,
      payload: Http.UpdateOrganizationPayload,
    ) => Promise<Http.OrganizationView>;
    readonly delete: (organizationId: string) => Promise<void>;
    /** Record the active organization on the session (`null` clears it). */
    readonly setActive: (
      payload: Http.SetActiveOrganizationPayload,
    ) => Promise<Http.StatusResponse>;

    /** Omit `role` to use the organization's default role. */
    readonly addMember: (
      organizationId: string,
      payload: Http.AddMemberPayload,
    ) => Promise<Http.MemberView>;
    /** Change a membership's role; `memberId` is the membership's own `id`. */
    readonly updateMemberRole: (
      memberId: string,
      payload: Http.UpdateMemberRolePayload,
    ) => Promise<Http.MemberView>;
    readonly removeMember: (memberId: string) => Promise<void>;
    /**
     * Suspend a membership without deleting it: the row (and the member's
     * role, restored on reactivation) survives, but every permission check in
     * the organization now denies them. Application sessions are left alone -
     * the server exposes an `onMemberDeactivated` hook for apps that want to
     * end them.
     */
    readonly deactivateMember: (memberId: string) => Promise<Http.MemberView>;
    readonly reactivateMember: (memberId: string) => Promise<Http.MemberView>;
    /** Set the role members added without one receive (owner-only). */
    readonly setDefaultRole: (
      organizationId: string,
      payload: Http.SetDefaultRolePayload,
    ) => Promise<Http.OrganizationView>;

    readonly invite: (
      organizationId: string,
      payload: Http.InviteMemberPayload,
    ) => Promise<Http.InvitationView>;
    readonly listInvitations: (organizationId: string) => Promise<Http.InvitationListView>;
    /**
     * Accept an invitation addressed to the signed-in user's email, with the
     * secret `token` the invitation email's link carried.
     */
    readonly acceptInvitation: (invitationId: string, token: string) => Promise<Http.MemberView>;
    /** Decline an invitation, with the secret `token` its email carried. */
    readonly rejectInvitation: (
      invitationId: string,
      token: string,
    ) => Promise<Http.InvitationView>;
    readonly cancelInvitation: (invitationId: string) => Promise<Http.InvitationView>;
    /** Re-send a pending invitation: same id, a fresh token and expiry, delivered again. */
    readonly resendInvitation: (invitationId: string) => Promise<Http.InvitationView>;

    /** Email domains the organization has claimed, and their verification state. */
    readonly listDomains: (organizationId: string) => Promise<Http.OrganizationDomainListView>;
    /**
     * Claim a domain, always proved through DNS: the answer carries the
     * `verificationToken` to publish as a TXT record. Only the operator
     * attests a domain manually ({@link AuthClient.admin.attestDomain}).
     */
    readonly addDomain: (
      organizationId: string,
      payload: Http.AddOrganizationDomainPayload,
    ) => Promise<Http.OrganizationDomainView>;
    /** Release a claim; `domainId` is the claim's own `id`. */
    readonly removeDomain: (domainId: string) => Promise<void>;
    /**
     * Run the DNS check. A claim whose record is not published yet comes back
     * in state `"failed"` - retry once it is.
     */
    readonly verifyDomain: (domainId: string) => Promise<Http.OrganizationDomainView>;

    /**
     * Define a role for one organization. A role it already defines is
     * refused with `409`: change it with {@link updateRole}.
     */
    readonly createRole: (
      organizationId: string,
      payload: Http.CreateOrgRolePayload,
    ) => Promise<Http.OrgRoleView>;
    readonly listRoles: (organizationId: string) => Promise<Http.OrgRoleListView>;
    /** Replace a role definition's permissions; `roleId` is the definition's own `id`. */
    readonly updateRole: (
      roleId: string,
      payload: Http.UpsertOrgRolePayload,
    ) => Promise<Http.OrgRoleView>;
    readonly deleteRole: (roleId: string) => Promise<void>;

    readonly createTeam: (
      organizationId: string,
      payload: Http.CreateTeamPayload,
    ) => Promise<Http.TeamView>;
    readonly listTeams: (organizationId: string) => Promise<Http.TeamListView>;
    /** The teams a membership's user belongs to; `memberId` is the membership's own `id`. */
    readonly listTeamsForMember: (memberId: string) => Promise<Http.TeamListView>;
    readonly updateTeam: (
      teamId: string,
      payload: Http.UpdateTeamPayload,
    ) => Promise<Http.TeamView>;
    readonly deleteTeam: (teamId: string) => Promise<void>;
    readonly addTeamMember: (
      teamId: string,
      payload: Http.AddTeamMemberPayload,
    ) => Promise<Http.TeamMemberView>;
    readonly listTeamMembers: (teamId: string) => Promise<Http.TeamMemberListView>;
    /** Remove a team membership; `teamMemberId` is its own `id` (from `addTeamMember` or `listTeamMembers`). */
    readonly removeTeamMember: (teamMemberId: string) => Promise<void>;
  };

  /** API keys owned by the signed-in user. 404 when unconfigured. */
  readonly apiKeys: {
    /** The plaintext key is returned exactly once — show it, then discard. */
    readonly create: (payload: Http.ApiKeyCreatePayload) => Promise<Http.ApiKeyCreatedView>;
    readonly list: () => Promise<Http.ApiKeyListView>;
    readonly update: (keyId: string, payload: Http.ApiKeyUpdatePayload) => Promise<Http.ApiKeyView>;
    readonly delete: (keyId: string) => Promise<void>;
  };

  /** Administration. The actor must satisfy the server's `isAdmin`; 403 otherwise. */
  readonly admin: {
    readonly listUsers: (payload: Http.AdminListUsersPayload) => Promise<Http.AdminUserListView>;
    readonly setRole: (payload: Http.AdminSetRolePayload) => Promise<Http.UserView>;
    readonly banUser: (payload: Http.AdminBanUserPayload) => Promise<Http.UserView>;
    /** Lift the ban; resolves once it is gone (the user is not returned). */
    readonly unbanUser: (payload: Http.AdminUserActionPayload) => Promise<void>;
    readonly removeUser: (payload: Http.AdminUserActionPayload) => Promise<void>;
    readonly revokeSessions: (payload: Http.AdminUserActionPayload) => Promise<Http.StatusResponse>;
    /** Assume another user's identity — swaps the session cookie. */
    readonly impersonate: (payload: Http.AdminUserActionPayload) => Promise<Http.AuthSuccess>;
    readonly stopImpersonating: () => Promise<Http.StatusResponse>;
    /**
     * Attest, as the operator and after checking ownership out of band, that
     * an organization controls a domain (`POST /admin/organization-domains`);
     * resolves with its claim, `verified` with the `manual` strategy and the
     * signed-in admin as its `attestedBy`.
     */
    readonly attestDomain: (
      payload: Http.AdminAttestDomainPayload,
    ) => Promise<Http.OrganizationDomainView>;
    /**
     * Release, as the operator, any organization's claim on a domain, whatever
     * its state (`DELETE /admin/organization-domains/:id`, #680): `domainId`
     * is the claim's own `id`. Resolves once it is gone.
     */
    readonly releaseDomain: (domainId: string) => Promise<void>;
  };

  /** Enterprise SSO (this server as an OIDC/SAML relying party). */
  readonly sso: {
    /** Register a connection (admin-gated). */
    readonly register: (payload: Http.SsoRegisterPayload) => Promise<Http.SsoProviderView>;
    /** Resolve the IdP authorization URL to redirect the browser to. */
    readonly signIn: (payload: Http.SsoSignInPayload) => Promise<Http.SsoUrlView>;
    /** Complete the callback and issue a session. */
    readonly callback: (payload: Http.SsoCallbackPayload) => Promise<Http.AuthSuccess>;
  };

  /**
   * OIDC provider surfaces a first-party app drives: client management
   * (admin-gated) and the consent page's decision. The protocol endpoints
   * themselves (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`,
   * discovery) are for OAuth clients, not this SDK.
   */
  readonly oidc: {
    readonly registerClient: (
      payload: Http.OidcRegisterClientPayload,
    ) => Promise<Http.OidcClientCreatedView>;
    readonly listClients: () => Promise<Http.OidcClientListView>;
    readonly updateClient: (
      clientId: string,
      payload: Http.OidcClientUpdatePayload,
    ) => Promise<Http.OidcClientView>;
    readonly deleteClient: (clientId: string) => Promise<void>;
    /** Post the consent decision; the response carries the redirect URL. */
    readonly consent: (payload: Http.OidcConsentPayload) => Promise<Http.OidcRedirectView>;
  };

  /** Extend this client with a plugin's typed methods. */
  readonly extend: <TExtension extends object>(
    plugin: AuthClientPlugin<TExtension>,
  ) => AuthClient & TExtension;
}

/**
 * Create an auth client for an effect-auth server.
 *
 * ```ts skip-type-checking
 * const client = createAuthClient({ baseUrl: "/api/auth" });
 * const { user } = await client.signIn({ email, password });
 * ```
 *
 * The session, as Atoms over this client, is `makeSessionAtoms(client)` from
 * `@thomasfosterau/effect-auth/client/atoms`.
 */
export const createAuthClient = (options: AuthClientOptions): AuthClient => {
  const baseUrl = options.baseUrl.replace(/\/$/, "");
  // Bind lazily so tests can swap `globalThis.fetch` after client creation.
  const doFetch: typeof globalThis.fetch =
    options.fetch ?? ((...args) => globalThis.fetch(...args));

  const send = async <T>(
    method: string,
    path: string,
    body: unknown,
    mediaType: string | undefined,
  ): Promise<T> => {
    const response = await doFetch(`${baseUrl}${path}`, {
      method,
      credentials: "include",
      headers: {
        ...(mediaType !== undefined && { accept: mediaType }),
        ...(body !== undefined && { "content-type": mediaType ?? "application/json" }),
        ...options.headers,
      },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      let message = response.statusText || `HTTP ${response.status}`;
      if (isJson(response)) {
        // A body that fails to parse leaves the status text as the message.
        const parsed: unknown = await response.json().catch(() => null);
        message = errorMessage(parsed) ?? message;
      }
      throw new AuthClientError(response.status, message);
    }
    if (response.status === 204 || !isJson(response)) {
      // SAFETY: endpoints that answer 204 or a non-JSON body are requested
      // with `T = void`, so `undefined` is their success value.
      return undefined as T;
    }
    // SAFETY: each call site names as `T` the success type the HTTP contract
    // declares for that endpoint, which is what the server encodes.
    return (await response.json()) as T;
  };

  const request = <T>(method: string, path: string, body?: unknown): Promise<T> =>
    send<T>(method, path, body, undefined);

  /** A request to a JSON:API resource group: `application/vnd.api+json` both ways. */
  const jsonApi = <T>(method: string, path: string, body?: unknown): Promise<T> =>
    send<T>(method, path, body, JSON_API);

  // --- Session observers -----------------------------------------------------

  const sessionListeners = new Set<SessionChangeListener>();

  const getSession = (): Promise<Http.SessionWithUserView | null> =>
    jsonApi<DataDocument<WireSession>>("GET", "/sessions/current?include=user").then(
      (document): Http.SessionWithUserView => {
        const session = sessionView(document.data);
        return { session, user: includedUser(document, session.userId) };
      },
      (error) => {
        if (error instanceof AuthClientError && error.status === 401) return null;
        throw error;
      },
    );

  /** Run every session observer and wait for all of them; a rejection is not the caller's. */
  const notifySessionChange = async (): Promise<void> => {
    await Promise.allSettled([...sessionListeners].map(async (listener) => listener()));
  };

  /**
   * Run a session-changing call, then notify the session observers. With none
   * registered (nothing observes the session) no refetch happens at all.
   */
  const mutating = async <T>(run: () => Promise<T>): Promise<T> => {
    const result = await run();
    await notifySessionChange();
    return result;
  };

  const pluginContext: AuthClientPluginContext = { request, mutating };

  /** Sign in with `credential` (`POST /sessions`), notifying the session observers. */
  const signInWith = (credential: Http.SignInCredential, rememberMe?: boolean) =>
    mutating(() =>
      jsonApi<SignInDocument>("POST", "/sessions", {
        data: {
          type: "sessions",
          attributes: { credential, ...(rememberMe !== undefined && { rememberMe }) },
        },
      }).then(authResult),
    );

  /** Send a one-time code or a magic link (`POST /otp-challenges`). */
  const sendChallenge = (
    attributes: Http.OtpChallengeDocument["data"]["attributes"],
  ): Promise<Http.StatusResponse> =>
    jsonApi<void>("POST", "/otp-challenges", { data: { type: "otp-challenges", attributes } }).then(
      () => ({ status: true }),
    );

  /** `PATCH /organizations/:id` with the attributes to change. */
  const updateOrganization = (
    organizationId: string,
    attributes: Http.UpdateOrganizationPayload & { readonly defaultRole?: string | undefined },
  ): Promise<Http.OrganizationView> =>
    jsonApi<DataDocument<WireOrganization>>(
      "PATCH",
      `/organizations/${encodeURIComponent(organizationId)}`,
      { data: { type: "organizations", id: organizationId, attributes } },
    ).then((document) => organizationView(document.data));

  /** `PATCH /organization-members/:id`: a new role, or a status to move to. */
  const updateMember = (
    memberId: string,
    attributes: {
      readonly role?: string | undefined;
      readonly status?: Http.MemberView["status"] | undefined;
    },
  ): Promise<Http.MemberView> =>
    jsonApi<DataDocument<WireMember>>(
      "PATCH",
      `/organization-members/${encodeURIComponent(memberId)}`,
      { data: { type: "organization-members", id: memberId, attributes } },
    ).then((document) => memberView(document.data));

  /** `GET /organizations/:id/<collection>`: an organization's domains, roles or teams. */
  const listOwned = <A>(organizationId: string, collection: string) =>
    jsonApi<CollectionDocument<A>>(
      "GET",
      `/organizations/${encodeURIComponent(organizationId)}/${collection}`,
    ).then((document) => document.data.map(organizationOwned));

  /** `POST /organizations/:id/<collection>`: create one `type` resource from `attributes`. */
  const createOwned = <A>(
    organizationId: string,
    collection: string,
    type: string,
    attributes: object,
  ) =>
    jsonApi<DataDocument<A>>(
      "POST",
      `/organizations/${encodeURIComponent(organizationId)}/${collection}`,
      { data: { type, attributes } },
    ).then((document) => organizationOwned(document.data));

  /** `PATCH /invitations/:id`: move an invitation to `status`, the invitee presenting its `token`. */
  const transitionInvitation = (
    invitationId: string,
    status: Exclude<Http.InvitationView["status"], "pending">,
    token?: string,
  ): Promise<InvitationTransitionDocument> =>
    jsonApi<InvitationTransitionDocument>(
      "PATCH",
      `/invitations/${encodeURIComponent(invitationId)}`,
      {
        data: {
          type: "invitations",
          id: invitationId,
          attributes: token === undefined ? { status } : { status, token },
        },
      },
    );

  /**
   * Approve or deny a device's user code (`POST /device-authorizations/decisions`).
   * The code travels in the body, never in the URL.
   */
  const decideDevice = (
    userCode: string,
    decision: "approved" | "denied",
  ): Promise<Http.StatusResponse> =>
    jsonApi<void>("POST", "/device-authorizations/decisions", {
      data: { type: "device-authorization-decisions", attributes: { userCode, decision } },
    }).then(() => ({ status: true }));

  /** Redeem a second-factor challenge with a TOTP or backup code. */
  const verifySecondFactor = (
    token: string,
    method: "totp" | "backup-code",
    code: string,
  ): Promise<AuthResult> =>
    mutating(() =>
      jsonApi<SignInDocument>("POST", "/second-factor-challenges/verifications", {
        data: {
          type: "second-factor-verifications",
          attributes: { method, code },
          // The challenge token travels in the body, never in the URL.
          relationships: { challenge: { data: { type: "second-factor-challenges", id: token } } },
        },
      }).then(authResult),
    );

  /**
   * Bind a pending second-factor challenge to the verify endpoints, refusing
   * client-side once the challenge window has passed (the server enforces the
   * same expiry — this just saves a doomed round trip).
   */
  const continuation = (challenge: Http.SecondFactorChallengeView): SecondFactorContinuation => {
    const isExpired = (): boolean => Date.now() >= challenge.expiresAt;
    const verify = (method: "totp" | "backup-code", code: string): Promise<AuthResult> => {
      if (isExpired()) {
        return Promise.reject(
          new SecondFactorChallengeError(
            "expired",
            "The second-factor challenge has expired — sign in again",
          ),
        );
      }
      return verifySecondFactor(challenge.token, method, code);
    };
    return {
      token: challenge.token,
      expiresAt: challenge.expiresAt,
      isExpired,
      verifyTotp: (code) => verify("totp", code),
      verifyBackupCode: (code) => verify("backup-code", code),
    };
  };

  // Use `let` so the `extend` closure can reference `self` after assignment.
  let self!: AuthClient;
  self = {
    onSessionChange: (listener) => {
      // A fresh entry per registration, so registering one listener twice
      // takes two removals, as with `addEventListener`'s distinct handlers.
      const entry: SessionChangeListener = () => listener();
      sessionListeners.add(entry);
      return () => {
        sessionListeners.delete(entry);
      };
    },
    invalidateSession: notifySessionChange,

    signUp: (payload) =>
      mutating(() =>
        jsonApi<SignInDocument>("POST", "/users", {
          data: { type: "users", attributes: payload },
        }).then(authResult),
      ),
    signIn: ({ email, password, captchaToken, rememberMe }) =>
      signInWith(
        {
          method: "password",
          email,
          password,
          ...(captchaToken !== undefined && { captchaToken }),
        },
        rememberMe,
      ),
    signOut: () =>
      mutating(async () => {
        await jsonApi<void>("DELETE", "/sessions/current");
      }),
    signInAnonymous: () => signInWith({ method: "anonymous" }),
    signInUsername: ({ username, password, captchaToken, rememberMe }) =>
      signInWith(
        {
          method: "username",
          username,
          password,
          ...(captchaToken !== undefined && { captchaToken }),
        },
        rememberMe,
      ),
    getSession,
    sendVerificationEmail: ({ email }) =>
      jsonApi<void>("POST", "/email-verifications", {
        data: { type: "email-verifications", attributes: { email } },
      }).then(() => ({ status: true })),
    verifyEmail: ({ token }) =>
      mutating(() =>
        jsonApi<SignInDocument | undefined>("POST", "/email-verifications/redemptions", {
          data: { type: "email-verification-redemptions", attributes: { token } },
        }).then(authResult),
      ),
    passwordResetRequest: ({ email }) =>
      jsonApi<void>("POST", "/password-resets", {
        data: { type: "password-resets", attributes: { email } },
      }).then(() => ({ status: true })),
    passwordResetConfirm: ({ token, newPassword }) =>
      jsonApi<void>("POST", "/password-resets/redemptions", {
        data: { type: "password-reset-redemptions", attributes: { token, newPassword } },
      }).then(() => ({ status: true })),
    changePassword: (payload) =>
      jsonApi<void>("PATCH", "/users/me/password", {
        data: { type: "user-passwords", id: "me", attributes: payload },
      }),
    updateUser: (payload) =>
      mutating(() =>
        jsonApi<DataDocument<WireUser>>("PATCH", "/users/me", {
          data: { type: "users", id: "me", attributes: payload },
        }).then((document) => userView(document.data)),
      ),
    listSessions: () =>
      jsonApi<CollectionDocument<WireSession>>("GET", "/sessions").then((document) =>
        document.data.map(sessionView),
      ),
    revokeSession: (sessionId) =>
      jsonApi<void>("DELETE", `/sessions/${encodeURIComponent(sessionId)}`),
    revokeOtherSessions: () => jsonApi<void>("DELETE", "/sessions?filter%5Bcurrent%5D=false"),
    jwtToken: () =>
      jsonApi<DataDocument<Http.JwtTokenView>>("POST", "/tokens").then(
        (document) => document.data.attributes,
      ),
    jwks: () => request<Http.JwksView>("GET", "/jwks"),

    identifiers: {
      list: () =>
        jsonApi<CollectionDocument<WireIdentifier>>("GET", "/identifiers").then((document) =>
          document.data.map(identifierView),
        ),
      delete: (identifierId) =>
        jsonApi<void>("DELETE", `/identifiers/${encodeURIComponent(identifierId)}`),
    },

    changeEmail: {
      request: (payload) =>
        jsonApi<void>("POST", "/email-changes", {
          data: { type: "email-changes", attributes: payload },
        }).then(() => ({ status: true })),
      confirm: (payload) =>
        mutating(() =>
          jsonApi<void>("POST", "/email-changes/redemptions", {
            data: { type: "email-change-redemptions", attributes: payload },
          }).then(() => ({ status: true })),
        ),
    },

    deleteUser: {
      request: () =>
        jsonApi<void>("POST", "/account-deletions", {
          data: { type: "account-deletions" },
        }).then(() => ({ status: true })),
      confirm: (payload) =>
        mutating(() =>
          jsonApi<void>("POST", "/account-deletions/redemptions", {
            data: { type: "account-deletion-redemptions", attributes: payload },
          }).then(() => ({ status: true })),
        ),
    },

    multiSession: {
      list: () =>
        jsonApi<CollectionDocument<WireDeviceSession>>("GET", "/device-sessions").then((document) =>
          document.data.flatMap((resource) => deviceSessionView(resource, document.included ?? [])),
        ),
      setActive: ({ sessionId }) =>
        mutating(() =>
          jsonApi<void>("PATCH", "/device-sessions/active", {
            data: { type: "device-sessions", id: sessionId },
          }).then(() => ({ status: true })),
        ),
      revoke: ({ sessionId }) =>
        mutating(() =>
          jsonApi<void>("DELETE", `/device-sessions/${encodeURIComponent(sessionId)}`).then(() => ({
            status: true,
          })),
        ),
    },

    magicLink: {
      send: ({ email }) => sendChallenge({ channel: "magic-link", email }),
      verify: ({ token }) => signInWith({ method: "magic-link", token }),
    },

    emailOtp: {
      send: ({ email, purpose }) => sendChallenge({ channel: "email", email, purpose }),
      signIn: ({ email, otp }) => signInWith({ method: "email-otp", email, otp }),
    },

    phoneOtp: {
      send: ({ phoneNumber, purpose }) => sendChallenge({ channel: "phone", phoneNumber, purpose }),
      signIn: ({ phoneNumber, otp }) => signInWith({ method: "phone-otp", phoneNumber, otp }),
    },

    googleOneTap: {
      nonce: () =>
        jsonApi<DataDocument<Record<string, never>>>("POST", "/google-one-tap-nonces").then(
          (document) => ({ nonce: document.data.id }),
        ),
      signIn: ({ credential, nonce }) =>
        signInWith({ method: "google-one-tap", idToken: credential, nonce }),
    },

    device: {
      code: (payload) => request<Http.DeviceCodeView>("POST", "/device/code", payload ?? {}),
      token: (payload) =>
        mutating(() => request<Http.AuthSuccess>("POST", "/device/token", payload)),
      approve: ({ userCode }) => decideDevice(userCode, "approved"),
      deny: ({ userCode }) => decideDevice(userCode, "denied"),
    },

    multiFactor: {
      enable: (payload) =>
        jsonApi<{ readonly meta: Http.MultiFactorEnableView }>(
          "POST",
          "/multi-factor-enrollments",
          {
            data: { type: "multi-factor-enrollments", attributes: payload },
          },
        ).then((document) => document.meta),
      confirm: (payload) =>
        jsonApi<void>("PATCH", "/multi-factor-enrollments/current", {
          data: { type: "multi-factor-enrollments", id: "current", attributes: payload },
        }).then(() => ({ status: true })),
      disable: (payload) =>
        jsonApi<void>("DELETE", "/multi-factor-enrollments/current", { meta: payload }).then(
          () => ({ status: true }),
        ),
      regenerateBackupCodes: (payload) =>
        jsonApi<{ readonly meta: Http.BackupCodesView }>("POST", "/backup-code-sets", {
          data: { type: "backup-code-sets", attributes: payload },
        }).then((document) => document.meta),
      verifyTotp: ({ token, code }) => verifySecondFactor(token, "totp", code),
      verifyBackupCode: ({ token, code }) => verifySecondFactor(token, "backup-code", code),
      challenge: continuation,
      continueChallenge: (result) => {
        if (result.secondFactor === undefined) {
          throw new SecondFactorChallengeError(
            "missing",
            "This result carries no second-factor challenge",
          );
        }
        return continuation(result.secondFactor);
      },
    },

    organization: {
      create: (payload) =>
        jsonApi<DataDocument<WireOrganization>>("POST", "/organizations", {
          data: { type: "organizations", attributes: payload },
        }).then((document) => organizationView(document.data)),
      list: () =>
        jsonApi<CollectionDocument<WireOrganization>>("GET", "/organizations").then((document) =>
          document.data.map(organizationView),
        ),
      get: async (organizationId) => {
        const path = `/organizations/${encodeURIComponent(organizationId)}`;
        const [organization, members] = await Promise.all([
          jsonApi<DataDocument<WireOrganization>>("GET", path),
          jsonApi<CollectionDocument<WireMember>>("GET", `${path}/members`),
        ]);
        return {
          organization: organizationView(organization.data),
          members: members.data.map(memberView),
        };
      },
      update: (organizationId, payload) => updateOrganization(organizationId, payload),
      delete: (organizationId) =>
        jsonApi<void>("DELETE", `/organizations/${encodeURIComponent(organizationId)}`),
      // The active organization is stored on the session, so notify its observers.
      setActive: ({ organizationId }) =>
        mutating(() =>
          jsonApi<void>("PATCH", "/organizations/active", {
            data: organizationId === null ? null : { type: "organizations", id: organizationId },
          }).then(() => ({ status: true })),
        ),

      addMember: (organizationId, { userId, role }) =>
        jsonApi<DataDocument<WireMember>>(
          "POST",
          `/organizations/${encodeURIComponent(organizationId)}/members`,
          {
            data: {
              type: "organization-members",
              ...(role !== undefined && { attributes: { role } }),
              relationships: { user: { data: { type: "users", id: userId } } },
            },
          },
        ).then((document) => memberView(document.data)),
      updateMemberRole: (memberId, { role }) => updateMember(memberId, { role }),
      removeMember: (memberId) =>
        jsonApi<void>("DELETE", `/organization-members/${encodeURIComponent(memberId)}`),
      deactivateMember: (memberId) => updateMember(memberId, { status: "inactive" }),
      reactivateMember: (memberId) => updateMember(memberId, { status: "active" }),
      setDefaultRole: (organizationId, { role }) =>
        updateOrganization(organizationId, { defaultRole: role }),

      invite: (organizationId, payload) =>
        jsonApi<DataDocument<WireInvitation>>(
          "POST",
          `/organizations/${encodeURIComponent(organizationId)}/invitations`,
          { data: { type: "invitations", attributes: payload } },
        ).then((document) => invitationView(document.data)),
      listInvitations: (organizationId) =>
        jsonApi<CollectionDocument<WireInvitation>>(
          "GET",
          `/organizations/${encodeURIComponent(organizationId)}/invitations`,
        ).then((document) => document.data.map(invitationView)),
      acceptInvitation: async (invitationId, token) => {
        const document = await transitionInvitation(invitationId, "accepted", token);
        const member = document.meta?.membership;
        if (member === undefined) {
          throw new AuthClientError(0, "The accepted invitation did not include its membership");
        }
        return memberView(member);
      },
      rejectInvitation: (invitationId, token) =>
        transitionInvitation(invitationId, "rejected", token).then((document) =>
          invitationView(document.data),
        ),
      cancelInvitation: (invitationId) =>
        transitionInvitation(invitationId, "canceled").then((document) =>
          invitationView(document.data),
        ),
      resendInvitation: (invitationId) =>
        jsonApi<DataDocument<WireInvitation>>(
          "POST",
          `/invitations/${encodeURIComponent(invitationId)}/deliveries`,
        ).then((document) => invitationView(document.data)),

      listDomains: (organizationId) =>
        jsonApi<CollectionDocument<WireDomain>>(
          "GET",
          `/organizations/${encodeURIComponent(organizationId)}/domains`,
        ).then((document) => document.data.map(domainView)),
      addDomain: (organizationId, attributes) =>
        jsonApi<DataDocument<WireDomain>>(
          "POST",
          `/organizations/${encodeURIComponent(organizationId)}/domains`,
          { data: { type: "organization-domains", attributes } },
        ).then((document) => domainView(document.data)),
      removeDomain: (domainId) =>
        jsonApi<void>("DELETE", `/organization-domains/${encodeURIComponent(domainId)}`),
      verifyDomain: (domainId) =>
        jsonApi<DataDocument<WireDomain>>(
          "POST",
          `/organization-domains/${encodeURIComponent(domainId)}/verifications`,
        ).then((document) => domainView(document.data)),

      createRole: (organizationId, attributes) =>
        createOwned<WireOrgRole>(organizationId, "roles", "organization-roles", attributes),
      listRoles: (organizationId) => listOwned<WireOrgRole>(organizationId, "roles"),
      updateRole: (roleId, attributes) =>
        jsonApi<DataDocument<WireOrgRole>>(
          "PATCH",
          `/organization-roles/${encodeURIComponent(roleId)}`,
          { data: { type: "organization-roles", id: roleId, attributes } },
        ).then((document) => organizationOwned(document.data)),
      deleteRole: (roleId) =>
        jsonApi<void>("DELETE", `/organization-roles/${encodeURIComponent(roleId)}`),

      createTeam: (organizationId, attributes) =>
        createOwned<WireTeam>(organizationId, "teams", "teams", attributes),
      listTeams: (organizationId) => listOwned<WireTeam>(organizationId, "teams"),
      listTeamsForMember: (memberId) =>
        jsonApi<CollectionDocument<WireTeam>>(
          "GET",
          `/organization-members/${encodeURIComponent(memberId)}/teams`,
        ).then((document) => document.data.map(organizationOwned)),
      updateTeam: (teamId, attributes) =>
        jsonApi<DataDocument<WireTeam>>("PATCH", `/teams/${encodeURIComponent(teamId)}`, {
          data: { type: "teams", id: teamId, attributes },
        }).then((document) => organizationOwned(document.data)),
      deleteTeam: (teamId) => jsonApi<void>("DELETE", `/teams/${encodeURIComponent(teamId)}`),
      addTeamMember: (teamId, { userId }) =>
        jsonApi<DataDocument<WireTeamMember>>(
          "POST",
          `/teams/${encodeURIComponent(teamId)}/members`,
          {
            data: {
              type: "team-members",
              relationships: { user: { data: { type: "users", id: userId } } },
            },
          },
        ).then((document) => teamMemberView(document.data)),
      listTeamMembers: (teamId) =>
        jsonApi<CollectionDocument<WireTeamMember>>(
          "GET",
          `/teams/${encodeURIComponent(teamId)}/members`,
        ).then((document) => document.data.map(teamMemberView)),
      removeTeamMember: (teamMemberId) =>
        jsonApi<void>("DELETE", `/team-members/${encodeURIComponent(teamMemberId)}`),
    },

    apiKeys: {
      create: (attributes) =>
        jsonApi<DataDocument<WireApiKey> & { readonly meta: { readonly key: string } }>(
          "POST",
          "/api-keys",
          { data: { type: "api-keys", attributes } },
        ).then((document) => ({ key: document.meta.key, apiKey: apiKeyView(document.data) })),
      list: () =>
        jsonApi<CollectionDocument<WireApiKey>>("GET", "/api-keys").then((document) =>
          document.data.map(apiKeyView),
        ),
      update: (keyId, attributes) =>
        jsonApi<DataDocument<WireApiKey>>("PATCH", `/api-keys/${encodeURIComponent(keyId)}`, {
          data: { type: "api-keys", id: keyId, attributes },
        }).then((document) => apiKeyView(document.data)),
      delete: (keyId) => jsonApi<void>("DELETE", `/api-keys/${encodeURIComponent(keyId)}`),
    },

    admin: {
      listUsers: ({ limit, offset, searchEmail }) => {
        const query = new URLSearchParams();
        if (searchEmail !== undefined) query.set("filter[email]", searchEmail);
        if (offset !== undefined) query.set("page[offset]", String(offset));
        if (limit !== undefined) query.set("page[limit]", String(limit));
        const search = query.toString();
        return jsonApi<
          CollectionDocument<WireUser> & { readonly meta: { readonly total: number } }
        >("GET", search === "" ? "/admin/users" : `/admin/users?${search}`).then((document) => ({
          users: document.data.map(userView),
          total: document.meta.total,
        }));
      },
      setRole: ({ userId, role }) =>
        jsonApi<DataDocument<WireUser>>("PATCH", adminUserPath(userId), {
          data: { type: "users", id: userId, attributes: { role } },
        }).then((document) => userView(document.data)),
      banUser: ({ userId, reason, expiresIn }) =>
        jsonApi<DataDocument<unknown>>("POST", "/user-bans", {
          data: {
            type: "user-bans",
            attributes: { reason, expiresIn },
            relationships: { user: userLinkage(userId) },
          },
        }).then((document) => includedUser(document, userId)),
      unbanUser: ({ userId }) =>
        jsonApi<void>("DELETE", `/user-bans/${encodeURIComponent(userId)}`),
      removeUser: ({ userId }) => jsonApi<void>("DELETE", adminUserPath(userId)),
      revokeSessions: ({ userId }) =>
        jsonApi<void>("DELETE", `${adminUserPath(userId)}/sessions`).then(() => ({
          status: true,
        })),
      // Impersonation swaps the session cookie in both directions.
      impersonate: ({ userId }) =>
        mutating(() =>
          jsonApi<DataDocument<unknown>>("POST", "/impersonations", {
            data: { type: "impersonations", relationships: { user: userLinkage(userId) } },
          }).then((document) => ({
            user: includedUser(document, userId),
            needsEmailVerification: false,
          })),
        ),
      stopImpersonating: () =>
        mutating(() =>
          jsonApi<void>("DELETE", "/impersonations/current").then(() => ({ status: true })),
        ),
      attestDomain: ({ organizationId, domain }) =>
        jsonApi<DataDocument<WireDomain>>("POST", "/admin/organization-domains", {
          data: {
            type: "organization-domains",
            attributes: { domain },
            relationships: {
              organization: { data: { type: "organizations", id: organizationId } },
            },
          },
        }).then((document) => domainView(document.data)),
      releaseDomain: (domainId) =>
        jsonApi<void>("DELETE", `/admin/organization-domains/${encodeURIComponent(domainId)}`),
    },

    sso: {
      register: ({ organizationId, ...attributes }) =>
        jsonApi<DataDocument<WireSsoProvider>>("POST", "/sso-providers", {
          data: {
            type: "sso-providers",
            attributes,
            ...(organizationId !== undefined && {
              relationships: {
                organization: { data: { type: "organizations", id: organizationId } },
              },
            }),
          },
        }).then((document) => ssoProviderView(document.data)),
      signIn: (attributes) =>
        jsonApi<DataDocument<{ readonly url: string }>>("POST", "/sso-authorizations", {
          data: { type: "sso-authorizations", attributes },
        }).then((document) => ({ url: document.data.attributes.url, state: document.data.id })),
      callback: (payload) =>
        mutating(() => request<Http.AuthSuccess>("POST", "/sso/callback", payload)),
    },

    oidc: {
      registerClient: ({ type, ...attributes }) =>
        jsonApi<
          DataDocument<WireOAuthClient> & {
            readonly meta?: { readonly clientSecret?: string };
          }
        >("POST", "/oauth-clients", {
          data: { type: "oauth-clients", attributes: { ...attributes, clientType: type } },
        }).then((document) => {
          const clientSecret = document.meta?.clientSecret;
          return {
            client: oauthClientView(document.data),
            ...(clientSecret !== undefined && { clientSecret }),
          };
        }),
      listClients: () =>
        jsonApi<CollectionDocument<WireOAuthClient>>("GET", "/oauth-clients").then((document) =>
          document.data.map(oauthClientView),
        ),
      updateClient: (clientId, attributes) =>
        jsonApi<DataDocument<WireOAuthClient>>(
          "PATCH",
          `/oauth-clients/${encodeURIComponent(clientId)}`,
          { data: { type: "oauth-clients", id: clientId, attributes } },
        ).then((document) => oauthClientView(document.data)),
      deleteClient: (clientId) =>
        jsonApi<void>("DELETE", `/oauth-clients/${encodeURIComponent(clientId)}`),
      consent: (payload) => request<Http.OidcRedirectView>("POST", "/oauth2/consent", payload),
    },

    extend: <TExtension extends object>(
      plugin: AuthClientPlugin<TExtension>,
    ): AuthClient & TExtension =>
      // SAFETY: the fresh object receives every own property of `self` (an
      // `AuthClient`) and then of the plugin's `TExtension`, so it is both.
      Object.assign(Object.create(null), self, plugin.install(pluginContext)) as AuthClient &
        TExtension,
  };

  return self;
};
