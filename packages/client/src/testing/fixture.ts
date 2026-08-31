/**
 * Test-only fixture: a fully functional in-memory effect-auth server (the
 * real `Auth.HTTP.make` handler over in-memory stores) plus a cookie-jar `fetch`
 * so the browser-oriented client can be exercised end to end in-process.
 *
 * Excluded from the published build (see `tsconfig.json`).
 */
import * as Auth from "@thomasfosterau/effect-auth";
import { Effect, Layer } from "effect";

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
   */
  readonly features?: boolean;
  /** Mount the organization module (orgs, members, invitations, teams, roles). */
  readonly organization?: boolean;
  /** Enable multi-session device lists (several accounts in one browser). */
  readonly multiSession?: { readonly maximumSessions?: number };
}

export const makeServerFixture = (options: ServerFixtureOptions = {}) => {
  const usersById = new Map<string, Auth.User>();
  const identifierRecords = new Map<string, Auth.Identifier>();
  const passwordHashes = new Map<string, string>();
  const sessions = new Map<string, Auth.Session>();
  const verifications = new Map<string, Auth.Email.EmailVerification>();
  const resets = new Map<string, Auth.Password.PasswordResetToken>();
  let userSeq = 0;

  const createUser = (input: {
    readonly name?: string;
    readonly attributes?: Record<string, unknown>;
  }): Auth.User => {
    const now = new Date();
    const user: Auth.User = {
      id: `user-${++userSeq}`,
      ...(input.name !== undefined && { name: input.name }),
      createdAt: now,
      updatedAt: now,
      attributes: input.attributes ?? {},
    };
    usersById.set(user.id, user);
    return user;
  };

  const getUserById = (userId: string) => Effect.sync(() => usersById.get(userId) ?? null);

  const identifierStore = Auth.memoryIdentifierStore(identifierRecords);

  const sessionStore: typeof Auth.SessionStore.Service = {
    create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
    get: (sessionId) => Effect.sync(() => sessions.get(sessionId) ?? null),
    update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
    delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id);
      }),
    listByUserId: (userId) =>
      Effect.sync(() => [...sessions.values()].filter((session) => session.userId === userId)),
  };

  const userStore: typeof Auth.UserStore.Service = {
    get: getUserById,
    getCredentials: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
  };

  const emailPasswordStore: typeof Auth.Email.EmailPasswordStore.Service = {
    createUser: (input) => Effect.sync(() => createUser(input)),
    getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };

  const userServiceStore: typeof Auth.UserServiceStore.Service = {
    get: getUserById,
    update: (user) =>
      Effect.sync(() => {
        usersById.set(user.id, user);
        return user;
      }),
    delete: (userId) => Effect.sync(() => void usersById.delete(userId)),
  };

  const emailVerificationStore: typeof Auth.Email.EmailVerificationStore.Service = {
    create: (v) => Effect.sync(() => (verifications.set(v.token, v), v)),
    get: (token) => Effect.sync(() => verifications.get(token) ?? null),
    delete: (token) => Effect.sync(() => void verifications.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [token, v] of verifications)
          if (v.userId === userId) verifications.delete(token);
      }),
  };

  const passwordResetStore: typeof Auth.Password.PasswordResetStore.Service = {
    create: (reset) => Effect.sync(() => (resets.set(reset.token, reset), reset)),
    get: (token) => Effect.sync(() => resets.get(token) ?? null),
    delete: (token) => Effect.sync(() => void resets.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [token, reset] of resets) if (reset.userId === userId) resets.delete(token);
      }),
  };

  const passwordResetUserStore: typeof Auth.Password.PasswordResetUserStore.Service = {
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
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
  const sentPhoneOTPs: Array<{ readonly phoneNumber: string; readonly otp: string }> = [];

  const anonymousUserStore: typeof Auth.AnonymousUserStore.Service = {
    createAnonymousUser: () => Effect.sync(() => createUser({ attributes: { isAnonymous: true } })),
    deleteUser: (userId) => Effect.sync(() => void usersById.delete(userId)),
  };

  const accountTokens = new Map<string, Auth.AccountToken>();
  const accountStore: typeof Auth.AccountManagementStore.Service = {
    create: (token) => Effect.sync(() => (accountTokens.set(token.token, token), token)),
    get: (token) => Effect.sync(() => accountTokens.get(token) ?? null),
    delete: (token) => Effect.sync(() => void accountTokens.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [t, rec] of accountTokens) if (rec.userId === userId) accountTokens.delete(t);
      }),
  };

  const multiFactorRecords = new Map<string, Auth.MultiFactor.MultiFactorRecord>();
  const multiFactorStore: typeof Auth.MultiFactor.MultiFactorStore.Service = {
    get: (userId) => Effect.sync(() => multiFactorRecords.get(userId) ?? null),
    upsert: (record) => Effect.sync(() => (multiFactorRecords.set(record.userId, record), record)),
    delete: (userId) => Effect.sync(() => void multiFactorRecords.delete(userId)),
  };

  const pendingMultiFactors = new Map<string, Auth.MultiFactor.PendingMultiFactor>();
  const pendingMultiFactorStore: typeof Auth.MultiFactor.PendingMultiFactorStore.Service = {
    create: (pending) =>
      Effect.sync(() => (pendingMultiFactors.set(pending.token, pending), pending)),
    get: (token) => Effect.sync(() => pendingMultiFactors.get(token) ?? null),
    delete: (token) => Effect.sync(() => void pendingMultiFactors.delete(token)),
  };

  const phoneRecords = new Map<string, Auth.PhoneOTPRecord>();
  const phoneKey = (phone: string, purpose: Auth.PhoneOTPPurpose) => `${phone}:${purpose}`;
  const phoneOTPStore: typeof Auth.PhoneOTPStore.Service = {
    upsert: (record) =>
      Effect.sync(() => {
        phoneRecords.set(phoneKey(record.phoneNumber, record.purpose), record);
        return record;
      }),
    get: (phone, purpose) => Effect.sync(() => phoneRecords.get(phoneKey(phone, purpose)) ?? null),
    delete: (phone, purpose) =>
      Effect.sync(() => void phoneRecords.delete(phoneKey(phone, purpose))),
    incrementAttempts: (phone, purpose) =>
      Effect.sync(() => {
        const record = phoneRecords.get(phoneKey(phone, purpose));
        if (record === undefined) return 0;
        const updated = { ...record, attempts: record.attempts + 1 };
        phoneRecords.set(phoneKey(phone, purpose), updated);
        return updated.attempts;
      }),
  };
  const phoneOTPUserStore: typeof Auth.PhoneOTPUserStore.Service = {
    createUser: (input) => Effect.sync(() => createUser(input)),
  };

  const deviceRecords = new Map<string, Auth.DeviceAuthorizationRecord>();
  const deviceStore: typeof Auth.DeviceAuthorizationStore.Service = {
    create: (record) => Effect.sync(() => (deviceRecords.set(record.deviceCode, record), record)),
    getByDeviceCode: (deviceCode) => Effect.sync(() => deviceRecords.get(deviceCode) ?? null),
    getByUserCode: (userCode) =>
      Effect.sync(() => [...deviceRecords.values()].find((r) => r.userCode === userCode) ?? null),
    update: (record) => Effect.sync(() => (deviceRecords.set(record.deviceCode, record), record)),
    delete: (deviceCode) => Effect.sync(() => void deviceRecords.delete(deviceCode)),
    claimApproval: (deviceCode) =>
      Effect.sync(() => {
        const record = deviceRecords.get(deviceCode);
        if (record === undefined || record.status !== "approved") return null;
        deviceRecords.delete(deviceCode);
        return record;
      }),
  };

  const featureBase = Layer.mergeAll(
    core,
    Layer.succeed(Auth.AnonymousUserStore)(anonymousUserStore),
    Layer.succeed(Auth.AccountManagementStore)(accountStore),
    Layer.succeed(Auth.MultiFactor.MultiFactorStore)(multiFactorStore),
    Layer.succeed(Auth.MultiFactor.PendingMultiFactorStore)(pendingMultiFactorStore),
    Layer.succeed(Auth.PhoneOTPStore)(phoneOTPStore),
    Layer.succeed(Auth.PhoneOTPUserStore)(phoneOTPUserStore),
    Layer.succeed(Auth.DeviceAuthorizationStore)(deviceStore),
  );

  const multiFactorServiceLayer = Auth.MultiFactor.MultiFactorService.layer({
    issuer: "effect-auth-client-test",
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
    Auth.PhoneOTPService.layer({
      sendOTP: (phoneNumber, otp) =>
        Effect.sync(() => void sentPhoneOTPs.push({ phoneNumber, otp })),
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

  const orgs = new Map<string, Auth.Organization>();
  const members: Auth.Member[] = [];
  const invitations = new Map<string, Auth.Invitation>();
  const teams = new Map<string, Auth.Team>();
  const teamMembers: Auth.TeamMember[] = [];
  const orgRoles = new Map<string, Auth.OrgRole>();

  const organizationStore: typeof Auth.OrganizationStore.Service = {
    createOrganization: (org) => Effect.sync(() => (orgs.set(org.id, org), org)),
    getOrganizationById: (id) => Effect.succeed(orgs.get(id) ?? null),
    getOrganizationBySlug: (slug) =>
      Effect.succeed([...orgs.values()].find((o) => o.slug === slug) ?? null),
    updateOrganization: (org) => Effect.sync(() => (orgs.set(org.id, org), org)),
    deleteOrganization: (id) =>
      Effect.sync(() => {
        orgs.delete(id);
        for (const [key, role] of orgRoles) {
          if (role.organizationId === id) orgRoles.delete(key);
        }
        for (const [teamId, team] of teams) {
          if (team.organizationId !== id) continue;
          teams.delete(teamId);
          for (let i = teamMembers.length - 1; i >= 0; i--) {
            if (teamMembers[i]!.teamId === teamId) teamMembers.splice(i, 1);
          }
        }
      }),
    createMember: (member) => Effect.sync(() => (members.push(member), member)),
    getMember: (organizationId, userId) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
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
      Effect.sync(() => (invitations.set(invitation.id, invitation), invitation)),
    getInvitation: (id) => Effect.succeed(invitations.get(id) ?? null),
    updateInvitation: (invitation) =>
      Effect.sync(() => (invitations.set(invitation.id, invitation), invitation)),
    listInvitationsByOrganization: (organizationId) =>
      Effect.succeed([...invitations.values()].filter((i) => i.organizationId === organizationId)),
    listInvitationsByEmail: (email) =>
      Effect.succeed([...invitations.values()].filter((i) => i.email === email)),
    createTeam: (team) => Effect.sync(() => (teams.set(team.id, team), team)),
    getTeam: (teamId) => Effect.succeed(teams.get(teamId) ?? null),
    updateTeam: (team) =>
      Effect.sync(() => {
        if (!teams.has(team.id)) return null;
        teams.set(team.id, team);
        return team;
      }),
    deleteTeam: (teamId) =>
      Effect.sync(() => {
        teams.delete(teamId);
        for (let i = teamMembers.length - 1; i >= 0; i--) {
          if (teamMembers[i]!.teamId === teamId) teamMembers.splice(i, 1);
        }
      }),
    listTeams: (organizationId) =>
      Effect.succeed([...teams.values()].filter((t) => t.organizationId === organizationId)),
    addTeamMember: (teamId, userId) =>
      Effect.sync(() => {
        const teamMember: Auth.TeamMember = { teamId, userId, createdAt: Date.now() };
        teamMembers.push(teamMember);
        return teamMember;
      }),
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
          .map((m) => teams.get(m.teamId))
          .filter((t): t is Auth.Team => t !== undefined && t.organizationId === organizationId),
      ),
    upsertOrgRole: (role) =>
      Effect.sync(() => (orgRoles.set(`${role.organizationId} ${role.role}`, role), role)),
    getOrgRole: (organizationId, role) =>
      Effect.succeed(orgRoles.get(`${organizationId} ${role}`) ?? null),
    listOrgRoles: (organizationId) =>
      Effect.succeed([...orgRoles.values()].filter((r) => r.organizationId === organizationId)),
    deleteOrgRole: (organizationId, role) =>
      Effect.sync(() => void orgRoles.delete(`${organizationId} ${role}`)),
  };

  const organizationBase = Layer.mergeAll(
    core,
    Layer.succeed(Auth.OrganizationStore)(organizationStore),
  );
  const organizationLayer = Layer.mergeAll(
    organizationBase,
    Auth.OrganizationService.layer().pipe(Layer.provide(organizationBase)),
  );

  const services: Layer.Layer<Auth.HTTP.AuthServices> = Layer.mergeAll(
    core,
    options.features === true ? featureLayer : Layer.empty,
    options.organization === true ? organizationLayer : Layer.empty,
  ) as Layer.Layer<Auth.HTTP.AuthServices>;

  const { handler } = Auth.HTTP.make({
    services,
    cookie: { secure: false },
    ...(options.multiSession !== undefined && { multiSession: options.multiSession }),
  });

  /**
   * Claim a `username` login handle for a user (there is no HTTP endpoint for
   * it: usernames are registered by the app, then used at `/sign-in/username`).
   */
  const registerUsername = (userId: string, username: string): Auth.Identifier => {
    const identifier = Auth.makeIdentifier({ userId, type: "username", value: username });
    identifierRecords.set(identifier.id, identifier);
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
    sentPhoneOTPs,
  };
};

/**
 * A `fetch` that dispatches to an in-process handler and emulates the
 * browser's cookie jar (the client relies on `credentials: "include"`).
 */
export const makeCookieJarFetch = (
  handler: (request: Request) => Promise<Response>,
): typeof globalThis.fetch => {
  const jar = new Map<string, string>();

  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (jar.size > 0) {
      request.headers.set(
        "cookie",
        [...jar.entries()].map(([name, value]) => `${name}=${value}`).join("; "),
      );
    }
    const response = await handler(request);
    for (const setCookie of response.headers.getSetCookie()) {
      const [pair] = setCookie.split(";");
      const eq = (pair ?? "").indexOf("=");
      if (eq <= 0) continue;
      const name = pair!.slice(0, eq).trim();
      const value = pair!.slice(eq + 1).trim();
      if (value === "" || setCookie.toLowerCase().includes("max-age=0")) {
        jar.delete(name);
      } else {
        jar.set(name, value);
      }
    }
    return response;
  }) as typeof globalThis.fetch;
};
