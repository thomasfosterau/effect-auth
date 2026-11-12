/**
 * Test-only fixture: a fully functional in-memory effect-auth server (the
 * real `Http.make` handler over in-memory stores) plus a cookie-jar `fetch`
 * so the browser-oriented client can be exercised end to end in-process.
 *
 * Published as the `./client/testing` entry point
 * (`@thomasfosterau/effect-auth/client/testing`), which the root barrel never
 * re-exports.
 */
import * as Auth from "../../index.ts";
import * as Http from "../../http/index.ts";
import { memoryPhoneOtpStore, memorySessionStore } from "../../testing/MemoryStores.ts";
import { Clock, DateTime, Effect, Layer, MutableHashMap, MutableHashSet } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";

const HOUR = 60 * 60 * 1000;

// Low scrypt cost keeps the suite fast while exercising real hashing.
const hasher = Auth.Password.scryptHasher({ cost: 16384 });

/**
 * Which optional modules the fixture's server mounts. Everything is off by
 * default so the base fixture keeps answering 404 for unconfigured features
 * (the shape most tests assert against).
 */
export interface ServerFixtureOptions {
  /**
   * Mount the optional auth features: username + anonymous sign-in,
   * multi-factor (with the sign-in gate), account management
   * (change-email / delete-user), phone OTP and device authorization.
   *
   * The feature set includes an in-memory `RateLimiter`, because the core
   * requires one for device authorization. Device approve and deny are
   * therefore rate limited as in production: 5 attempts per user code per 15
   * minutes, then `429`. A test that approves or denies one code more than 5
   * times in a window sees the limit.
   */
  readonly features?: boolean;
  /**
   * Mount the organization module (orgs, members, invitations, domains, teams,
   * roles), including an in-memory domain store and a `DomainVerifier` that
   * answers `true` for the domains pushed into `publishedDnsDomains`.
   */
  readonly organization?: boolean;
  /** Enable multi-session device lists (several accounts in one browser). */
  readonly multiSession?: { readonly maximumSessions?: number };
  /**
   * The attribute keys a sign-up may set (`Http.make`'s `signUpAttributes`).
   * Default none: as in production, a sign-up keeps no attribute (#580).
   */
  readonly signUpAttributes?: ReadonlyArray<string> | undefined;
}

export const makeServerFixture = (options: ServerFixtureOptions = {}) => {
  const usersById = MutableHashMap.empty<string, Auth.User>();
  const identifierRecords = MutableHashMap.empty<string, Auth.Identifier>();
  const passwordHashes = MutableHashMap.empty<string, string>();
  const sessions = MutableHashMap.empty<string, Auth.Session>();
  const verifications = MutableHashMap.empty<string, Auth.Email.EmailVerification>();
  const resets = MutableHashMap.empty<string, Auth.Password.PasswordResetToken>();
  let userSeq = 0;

  const createUser = (input: {
    readonly name?: string;
    readonly attributes?: Auth.User["attributes"];
  }): Auth.User => {
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    const user: Auth.User = {
      id: `user-${++userSeq}`,
      ...(input.name !== undefined && { name: input.name }),
      createdAt: now,
      updatedAt: now,
      attributes: input.attributes ?? {},
    };
    MutableHashMap.set(usersById, user.id, user);
    return user;
  };

  const getUserById = (userId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(usersById, userId)));

  const identifierStore = Auth.memoryIdentifierStore(identifierRecords);

  const sessionStore = memorySessionStore(sessions);

  const userStore: typeof Auth.UserStore.Service = {
    get: getUserById,
  };

  const emailPasswordStore: typeof Auth.Email.EmailPasswordStore.Service = {
    createUser: (input) => Effect.sync(() => ({ user: createUser(input), created: true })),
    getPasswordHash: (userId) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(passwordHashes, userId))),
    clearPasswordHash: (userId: string) =>
      Effect.sync(() => void MutableHashMap.remove(passwordHashes, userId)),
    setPasswordHash: (userId, hash) =>
      Effect.sync(() => void MutableHashMap.set(passwordHashes, userId, hash)),
  };

  const userServiceStore: typeof Auth.UserServiceStore.Service = {
    get: getUserById,
    update: (user) =>
      Effect.sync(() => {
        MutableHashMap.set(usersById, user.id, user);
        return user;
      }),
    delete: (userId) => Effect.sync(() => void MutableHashMap.remove(usersById, userId)),
  };

  const emailVerificationStore: typeof Auth.Email.EmailVerificationStore.Service = {
    create: (v) => Effect.sync(() => (MutableHashMap.set(verifications, v.token, v), v)),
    get: (token) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(verifications, token))),
    delete: (token) => Effect.sync(() => void MutableHashMap.remove(verifications, token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        MutableHashMap.forEach(verifications, (v, token) => {
          if (v.userId === userId) MutableHashMap.remove(verifications, token);
        });
      }),
    getLatestByUserId: (userId) =>
      Effect.sync(() => {
        let latest: Auth.Email.EmailVerification | null = null;
        MutableHashMap.forEach(verifications, (v) => {
          if (v.userId === userId && (latest === null || v.createdAt > latest.createdAt)) {
            latest = v;
          }
        });
        return latest;
      }),
  };

  const passwordResetStore: typeof Auth.Password.PasswordResetStore.Service = {
    create: (reset) => Effect.sync(() => (MutableHashMap.set(resets, reset.token, reset), reset)),
    get: (token) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(resets, token))),
    delete: (token) => Effect.sync(() => void MutableHashMap.remove(resets, token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        MutableHashMap.forEach(resets, (reset, token) => {
          if (reset.userId === userId) MutableHashMap.remove(resets, token);
        });
      }),
  };

  const passwordResetUserStore: typeof Auth.Password.PasswordResetUserStore.Service = {
    setPasswordHash: (userId, hash) =>
      Effect.sync(() => void MutableHashMap.set(passwordHashes, userId, hash)),
  };

  const storeLayer = Layer.mergeAll(
    Layer.succeed(Auth.SessionStore)(sessionStore),
    Layer.succeed(Auth.UserStore)(userStore),
    Layer.succeed(Auth.IdentifierStore)(identifierStore),
    Layer.succeed(Auth.Email.EmailPasswordStore)(emailPasswordStore),
    Layer.succeed(Auth.Password.PasswordHasher)(hasher),
    Layer.succeed(Auth.Email.EmailVerificationStore)(emailVerificationStore),
    Layer.succeed(Auth.Password.PasswordResetStore)(passwordResetStore),
    Layer.succeed(Auth.Password.PasswordResetUserStore)(passwordResetUserStore),
    Layer.succeed(Auth.UserServiceStore)(userServiceStore),
    Auth.Hooks.Default,
  );

  const sessionServiceLayer = Auth.SessionService.layer({
    sessionExpiresIn: { activePeriod: HOUR, idlePeriod: HOUR },
  }).pipe(Layer.provide(storeLayer));

  // Stage 1: services needing only raw stores + Hooks + SessionService.
  const stage1 = Layer.mergeAll(
    storeLayer,
    sessionServiceLayer,
    Auth.UserService.layer().pipe(Layer.provide(storeLayer)),
    Auth.Email.EmailVerificationService.layer({ sendEmail: () => Effect.void }).pipe(
      Layer.provide(storeLayer),
    ),
  );

  // Stage 2: services needing stage-1 services (e.g. SessionService).
  const emailPasswordServiceLayer = Auth.Email.EmailPasswordService.layer().pipe(
    Layer.provide(stage1),
  );
  const passwordResetServiceLayer = Auth.Password.PasswordResetService.layer({
    sendResetPassword: () => Effect.void,
  }).pipe(Layer.provide(stage1));
  const stage2 = Layer.mergeAll(stage1, emailPasswordServiceLayer, passwordResetServiceLayer);

  // Stage 3: AuthLifecycleService needs EmailPasswordService + others from stage 2.
  const authLifecycleServiceLayer = Auth.AuthLifecycleService.layer().pipe(Layer.provide(stage2));

  const core = Layer.mergeAll(stage2, authLifecycleServiceLayer);

  // --- Optional feature modules (mounted only when asked for) ----------------
  //
  // Same staging rule as above: stores first, then the services that resolve
  // them at Layer-construction time. Delivery seams push into arrays so tests
  // can read the token/OTP a flow would have emailed or texted.

  const sentChangeEmail: Array<{ readonly newEmail: string; readonly token: string }> = [];
  const sentDeleteTokens: string[] = [];
  const sentPhoneOtps: Array<{ readonly phoneNumber: string; readonly otp: string }> = [];

  const anonymousUserStore: typeof Auth.AnonymousUserStore.Service = {
    createAnonymousUser: () => Effect.sync(() => createUser({ attributes: { isAnonymous: true } })),
    deleteUser: (userId) => Effect.sync(() => void MutableHashMap.remove(usersById, userId)),
  };

  const accountTokens = MutableHashMap.empty<string, Auth.AccountToken>();
  const accountStore: typeof Auth.AccountManagementStore.Service = {
    create: (token) =>
      Effect.sync(() => (MutableHashMap.set(accountTokens, token.token, token), token)),
    get: (token) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(accountTokens, token))),
    delete: (token) => Effect.sync(() => void MutableHashMap.remove(accountTokens, token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        MutableHashMap.forEach(accountTokens, (rec, t) => {
          if (rec.userId === userId) MutableHashMap.remove(accountTokens, t);
        });
      }),
  };

  const multiFactorRecords = MutableHashMap.empty<string, Auth.MultiFactor.MultiFactorRecord>();
  const multiFactorStore: typeof Auth.MultiFactor.MultiFactorStore.Service = {
    get: (userId) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(multiFactorRecords, userId))),
    upsert: (record) =>
      Effect.sync(() => (MutableHashMap.set(multiFactorRecords, record.userId, record), record)),
    delete: (userId) => Effect.sync(() => void MutableHashMap.remove(multiFactorRecords, userId)),
  };

  const pendingMultiFactors = MutableHashMap.empty<string, Auth.MultiFactor.PendingMultiFactor>();
  const pendingMultiFactorAttempts = MutableHashMap.empty<string, number>();
  const pendingMultiFactorStore: typeof Auth.MultiFactor.PendingMultiFactorStore.Service = {
    create: (pending) =>
      Effect.sync(() => (MutableHashMap.set(pendingMultiFactors, pending.token, pending), pending)),
    get: (token) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(pendingMultiFactors, token))),
    recordFailedAttempt: (token) =>
      Effect.sync(() => {
        const attempts =
          Option.getOrElse(MutableHashMap.get(pendingMultiFactorAttempts, token), () => 0) + 1;
        MutableHashMap.set(pendingMultiFactorAttempts, token, attempts);
        return attempts;
      }),
    delete: (token) =>
      Effect.sync(() => {
        MutableHashMap.remove(pendingMultiFactors, token);
        MutableHashMap.remove(pendingMultiFactorAttempts, token);
      }),
  };

  const phoneOtpUserStore: typeof Auth.PhoneOtpUserStore.Service = {
    createUser: (input) => Effect.sync(() => ({ user: createUser(input), created: true })),
  };

  const deviceRecords = MutableHashMap.empty<string, Auth.DeviceAuthorizationRecord>();
  const deviceStore: typeof Auth.DeviceAuthorizationStore.Service = {
    create: (record) =>
      Effect.sync(() => (MutableHashMap.set(deviceRecords, record.deviceCode, record), record)),
    getByDeviceCode: (deviceCode) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(deviceRecords, deviceCode))),
    getByUserCode: (userCode) =>
      Effect.sync(
        () =>
          Arr.fromIterable(MutableHashMap.values(deviceRecords)).find(
            (r) => r.userCode === userCode,
          ) ?? null,
      ),
    update: (record) =>
      Effect.sync(() => (MutableHashMap.set(deviceRecords, record.deviceCode, record), record)),
    delete: (deviceCode) =>
      Effect.sync(() => void MutableHashMap.remove(deviceRecords, deviceCode)),
    claimApproval: (deviceCode) =>
      Effect.sync(() => {
        const record = Option.getOrUndefined(MutableHashMap.get(deviceRecords, deviceCode));
        if (record === undefined || record.status !== "approved") return null;
        MutableHashMap.remove(deviceRecords, deviceCode);
        return record;
      }),
  };

  const featureBase = Layer.mergeAll(
    core,
    Layer.succeed(Auth.AnonymousUserStore)(anonymousUserStore),
    Layer.succeed(Auth.AccountManagementStore)(accountStore),
    Layer.succeed(Auth.MultiFactor.MultiFactorStore)(multiFactorStore),
    Layer.succeed(Auth.MultiFactor.PendingMultiFactorStore)(pendingMultiFactorStore),
    Layer.succeed(Auth.PhoneOtpStore)(memoryPhoneOtpStore()),
    Layer.succeed(Auth.PhoneOtpUserStore)(phoneOtpUserStore),
    Layer.succeed(Auth.DeviceAuthorizationStore)(deviceStore),
  );

  const multiFactorServiceLayer = Auth.MultiFactor.MultiFactorService.layer({
    issuer: "effect-auth-client-fixture",
  }).pipe(Layer.provide(featureBase));

  const featureLayer = Layer.mergeAll(
    featureBase,
    Auth.AnonymousService.layer().pipe(Layer.provide(featureBase)),
    Auth.UsernameService.layer().pipe(Layer.provide(featureBase)),
    Auth.AccountManagementService.layer({
      sendChangeEmailVerification: ({ newEmail, token }) =>
        Effect.sync(() => void sentChangeEmail.push({ newEmail, token })),
      sendDeleteAccountVerification: ({ token }) =>
        Effect.sync(() => void sentDeleteTokens.push(token)),
    }).pipe(Layer.provide(featureBase)),
    Auth.PhoneOtpService.layer({
      sendOtp: (phoneNumber, otp) =>
        Effect.sync(() => void sentPhoneOtps.push({ phoneNumber, otp })),
    }).pipe(Layer.provide(featureBase)),
    Auth.DeviceAuthorizationService.layer({
      verificationUri: "https://client.test/device",
      // interval 0 so back-to-back polls in one test never hit `slow_down`.
      interval: 0,
    }).pipe(Layer.provide(featureBase)),
    multiFactorServiceLayer,
    // The gate is what makes password sign-in answer with `secondFactor`.
    Auth.MultiFactor.MultiFactorGateLayer.pipe(Layer.provide(multiFactorServiceLayer)),
  );

  // --- Organization module ---------------------------------------------------

  const orgs = MutableHashMap.empty<string, Auth.Organization>();
  const members: Auth.Member[] = [];
  const invitations = MutableHashMap.empty<string, Auth.Invitation>();
  const teams = MutableHashMap.empty<string, Auth.Team>();
  const teamMembers: Auth.TeamMember[] = [];
  const removeTeamMembers = (teamId: string): void => {
    const kept = teamMembers.filter((m) => m.teamId !== teamId);
    teamMembers.splice(0, teamMembers.length, ...kept);
  };
  const orgRoles = MutableHashMap.empty<string, Auth.OrgRole>();
  const domainRecords = MutableHashMap.empty<string, Auth.OrganizationDomain>();
  /** Domains whose DNS TXT record the stub verifier should "find". */
  const publishedDnsDomains = MutableHashSet.empty<string>();

  const organizationStore: typeof Auth.OrganizationStore.Service = {
    createOrganization: (org) => Effect.sync(() => (MutableHashMap.set(orgs, org.id, org), org)),
    getOrganizationById: (id) => Effect.succeed(Option.getOrNull(MutableHashMap.get(orgs, id))),
    getOrganizationBySlug: (slug) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(orgs)).find((o) => o.slug === slug) ?? null,
      ),
    updateOrganization: (org) => Effect.sync(() => (MutableHashMap.set(orgs, org.id, org), org)),
    deleteOrganization: (id) =>
      Effect.sync(() => {
        MutableHashMap.remove(orgs, id);
        MutableHashMap.forEach(orgRoles, (role, key) => {
          if (role.organizationId === id) MutableHashMap.remove(orgRoles, key);
        });
        MutableHashMap.forEach(teams, (team, teamId) => {
          if (team.organizationId !== id) return;
          MutableHashMap.remove(teams, teamId);
          removeTeamMembers(teamId);
        });
      }),
    createMember: (member) => Effect.sync(() => (members.push(member), member)),
    getMember: (organizationId, userId) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
    getMemberById: (memberId) => Effect.succeed(members.find((m) => m.id === memberId) ?? null),
    updateMember: (member) =>
      Effect.sync(() => {
        const index = members.findIndex((m) => m.id === member.id);
        if (index >= 0) members[index] = member;
        return member;
      }),
    deleteMember: (memberId) =>
      Effect.sync(() => {
        const index = members.findIndex((m) => m.id === memberId);
        if (index >= 0) members.splice(index, 1);
      }),
    listMembersByOrganization: (organizationId) =>
      Effect.succeed(members.filter((m) => m.organizationId === organizationId)),
    listMembersByUser: (userId) => Effect.succeed(members.filter((m) => m.userId === userId)),
    countMembersByOrganization: (organizationId) =>
      Effect.succeed(members.filter((m) => m.organizationId === organizationId).length),
    createInvitation: (invitation) =>
      Effect.sync(() => (MutableHashMap.set(invitations, invitation.id, invitation), invitation)),
    getInvitation: (id) => Effect.succeed(Option.getOrNull(MutableHashMap.get(invitations, id))),
    updateInvitation: (invitation) =>
      Effect.sync(() => (MutableHashMap.set(invitations, invitation.id, invitation), invitation)),
    listInvitationsByOrganization: (organizationId) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(invitations)).filter(
          (i) => i.organizationId === organizationId,
        ),
      ),
    listInvitationsByEmail: (email) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(invitations)).filter((i) => i.email === email),
      ),
    createTeam: (team) => Effect.sync(() => (MutableHashMap.set(teams, team.id, team), team)),
    getTeam: (teamId) => Effect.succeed(Option.getOrNull(MutableHashMap.get(teams, teamId))),
    updateTeam: (team) =>
      Effect.sync(() => {
        if (!MutableHashMap.has(teams, team.id)) return null;
        MutableHashMap.set(teams, team.id, team);
        return team;
      }),
    deleteTeam: (teamId) =>
      Effect.sync(() => {
        MutableHashMap.remove(teams, teamId);
        removeTeamMembers(teamId);
      }),
    listTeams: (organizationId) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(teams)).filter(
          (t) => t.organizationId === organizationId,
        ),
      ),
    addTeamMember: (teamMember) => Effect.sync(() => (teamMembers.push(teamMember), teamMember)),
    getTeamMemberById: (teamMemberId) =>
      Effect.succeed(teamMembers.find((m) => m.id === teamMemberId) ?? null),
    removeTeamMember: (teamId, userId) =>
      Effect.sync(() => {
        const index = teamMembers.findIndex((m) => m.teamId === teamId && m.userId === userId);
        if (index >= 0) teamMembers.splice(index, 1);
      }),
    listTeamMembers: (teamId) => Effect.succeed(teamMembers.filter((m) => m.teamId === teamId)),
    listTeamsForMember: (organizationId, userId) =>
      Effect.succeed(
        teamMembers
          .filter((m) => m.userId === userId)
          .map((m) => Option.getOrUndefined(MutableHashMap.get(teams, m.teamId)))
          .filter((t): t is Auth.Team => t !== undefined && t.organizationId === organizationId),
      ),
    upsertOrgRole: (role) =>
      Effect.sync(
        () => (MutableHashMap.set(orgRoles, `${role.organizationId} ${role.role}`, role), role),
      ),
    getOrgRole: (organizationId, role) =>
      Effect.succeed(Option.getOrNull(MutableHashMap.get(orgRoles, `${organizationId} ${role}`))),
    getOrgRoleById: (orgRoleId) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(orgRoles)).find((r) => r.id === orgRoleId) ?? null,
      ),
    listOrgRoles: (organizationId) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(orgRoles)).filter(
          (r) => r.organizationId === organizationId,
        ),
      ),
    deleteOrgRole: (organizationId, role) =>
      Effect.sync(() => void MutableHashMap.remove(orgRoles, `${organizationId} ${role}`)),
  };

  const domainVerifier: typeof Auth.DomainVerifier.Service = {
    verify: (domain) => Effect.succeed(MutableHashSet.has(publishedDnsDomains, domain)),
  };

  const organizationBase = Layer.mergeAll(
    core,
    Layer.succeed(Auth.OrganizationStore)(organizationStore),
    Layer.succeed(Auth.OrganizationDomainStore)(Auth.memoryOrganizationDomainStore(domainRecords)),
    Layer.succeed(Auth.DomainVerifier)(domainVerifier),
  );
  const organizationLayer = Layer.mergeAll(
    organizationBase,
    Auth.OrganizationService.layer().pipe(Layer.provide(organizationBase)),
  );

  // The feature set mounts device authorization, whose user-code limit needs a
  // RateLimiter (Http.make throws without one, #389), so the feature set carries
  // an in-memory one. Device approve/deny are limited to 5 per user code per 15
  // minutes, as in production.
  const rateLimitEntries = MutableHashMap.empty<string, Auth.RateLimitEntry>();
  const rateLimitStore: typeof Auth.RateLimitStore.Service = {
    get: (key) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(rateLimitEntries, key))),
    set: (key, entry) => Effect.sync(() => void MutableHashMap.set(rateLimitEntries, key, entry)),
    increment: (key, ttl) =>
      // Starts a new window when there is none or it has expired, as the
      // RateLimitStore contract requires (#455).
      Effect.flatMap(Clock.currentTimeMillis, (now) =>
        Effect.sync(() => {
          const entry = Option.getOrUndefined(MutableHashMap.get(rateLimitEntries, key));
          const next: Auth.RateLimitEntry =
            entry === undefined || now >= entry.resetAt
              ? { key, count: 1, resetAt: now + ttl * 1000 }
              : { ...entry, count: entry.count + 1 };
          MutableHashMap.set(rateLimitEntries, key, next);
          return next.count;
        }),
      ),
    delete: (key) => Effect.sync(() => void MutableHashMap.remove(rateLimitEntries, key)),
  };
  const rateLimiterLayer = Auth.RateLimiter.layer().pipe(
    Layer.provide(Layer.succeed(Auth.RateLimitStore, rateLimitStore)),
  );

  const services: Layer.Layer<Http.AuthServices> = Layer.mergeAll(
    core,
    options.features === true ? Layer.merge(featureLayer, rateLimiterLayer) : Layer.empty,
    options.organization === true ? organizationLayer : Layer.empty,
  );

  // The fixture runs one in-process client, with no client address, so the
  // per-address IP limit `Http.make` applies by default is off (#583): it would
  // refuse every address-less request to a limited endpoint.
  const { handler } = Http.make({
    services,
    cookie: { secure: false },
    ipRateLimit: false,
    ...(options.multiSession !== undefined && { multiSession: options.multiSession }),
    ...(options.signUpAttributes !== undefined && { signUpAttributes: options.signUpAttributes }),
  });

  /**
   * Claim a `username` login handle for a user (there is no HTTP endpoint for
   * it: usernames are registered by the app, then used by a `POST /sessions` with a `username` credential).
   */
  const registerUsername = (userId: string, username: string): Auth.Identifier => {
    const identifier = Auth.makeIdentifier({
      userId,
      type: "username",
      value: username,
      now: DateTime.toDateUtc(DateTime.nowUnsafe()),
    });
    MutableHashMap.set(identifierRecords, identifier.id, identifier);
    return identifier;
  };

  return {
    handler,
    sessions,
    usersById,
    identifierRecords,
    registerUsername,
    /** Change-email verifications the server "sent" (newest last). */
    sentChangeEmail,
    /** Delete-account tokens the server "sent". */
    sentDeleteTokens,
    /** Phone OTPs the server "texted". */
    sentPhoneOtps,
    /** Domain claims the organization module stored. */
    domainRecords,
    /** Add a domain here to make the stub DNS verifier accept it. */
    publishedDnsDomains,
  };
};

/**
 * A `fetch` that dispatches to an in-process handler and emulates the
 * browser's cookie jar (the client relies on `credentials: "include"`).
 */
export const makeCookieJarFetch = (
  handler: (request: Request) => Promise<Response>,
): typeof globalThis.fetch => {
  const jar = MutableHashMap.empty<string, string>();

  return async (input, init) => {
    const request = new Request(input, init);
    if (MutableHashMap.size(jar) > 0) {
      request.headers.set(
        "cookie",
        Arr.fromIterable(jar)
          .map(([name, value]) => `${name}=${value}`)
          .join("; "),
      );
    }
    const response = await handler(request);
    Arr.forEach(response.headers.getSetCookie(), (setCookie) => {
      const [pair = ""] = setCookie.split(";");
      const eq = pair.indexOf("=");
      if (eq <= 0) return;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value === "" || setCookie.toLowerCase().includes("max-age=0")) {
        MutableHashMap.remove(jar, name);
      } else {
        MutableHashMap.set(jar, name, value);
      }
    });
    return response;
  };
};
