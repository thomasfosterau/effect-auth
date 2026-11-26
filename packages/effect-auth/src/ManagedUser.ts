/**
 * Which organization manages a user. SSO, SCIM and membership writes gate on
 * it, so one tenant's IdP or provisioning token never reaches an account that
 * belongs to someone else.
 *
 * @module managed-user
 */
import * as Effect from "effect/Effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import type { AuthError } from "./Errors.ts";
import { primaryEmail, type Identifier } from "./Identifier.ts";
import type { OrganizationDomainStore } from "./Organization.ts";
import type * as Types from "./Types.ts";

/**
 * `User.attributes` key holding {@link ProvisionedBy}: written once, when an
 * SSO provider or a SCIM connection creates the user, and never by a caller
 * (it is one of `SIGN_UP_PROTECTED_ATTRIBUTES`).
 *
 * @since 0.1.0
 * @category constants
 */
export const PROVISIONED_BY_ATTRIBUTE = "provisionedBy";

/**
 * The connection that created a user.
 *
 * @since 0.1.0
 * @category models
 */
export const ProvisionedBy = Schema.Struct({
  kind: Schema.Literals(["sso", "scim"]),
  /** The SSO provider's or SCIM connection's id. */
  connectionId: Schema.String,
  /** The connection's organization; absent for an SSO provider registered without one. */
  organizationId: Schema.optional(Schema.String),
});

/**
 * @since 0.1.0
 * @category models
 */
export type ProvisionedBy = typeof ProvisionedBy.Type;

const decodeProvisionedBy = Schema.decodeUnknownOption(ProvisionedBy);

/**
 * The connection that created `user`, or `None` for a user no connection
 * created (or whose stamp does not decode).
 *
 * @since 0.1.0
 * @category getters
 */
export const provisionedBy = (user: Types.User): Option.Option<ProvisionedBy> =>
  decodeProvisionedBy(user.attributes[PROVISIONED_BY_ATTRIBUTE]);

/** Whether `user` carries a stamp from one of `organizationId`'s connections. */
const stampedBy = (user: Types.User, organizationId: string): boolean =>
  Option.exists(provisionedBy(user), (by) => by.organizationId === organizationId);

/**
 * The attributes that stamp a new user as created by `by`.
 *
 * @since 0.1.0
 * @category constructors
 */
export const provisionedByAttributes = (by: ProvisionedBy): Types.Attributes => ({
  [PROVISIONED_BY_ATTRIBUTE]: {
    kind: by.kind,
    connectionId: by.connectionId,
    ...(by.organizationId !== undefined && { organizationId: by.organizationId }),
  },
});

/**
 * The normalized domain of an email address (after its last `@`), or `""`.
 *
 * @since 0.1.0
 * @category utils
 */
export const emailDomain = (email: string): string => {
  const at = email.lastIndexOf("@");
  return at === -1
    ? ""
    : email
        .slice(at + 1)
        .trim()
        .toLowerCase();
};

/**
 * Whether `email` sits on one of `domains` (normalized, as
 * {@link verifiedDomains} answers them). Subdomains do not match.
 *
 * @since 0.1.0
 * @category predicates
 */
export const isOnDomains = (email: string, domains: ReadonlyArray<string>): boolean => {
  const domain = emailDomain(email);
  return domain !== "" && Arr.contains(domains, domain);
};

/**
 * The organization's verified domain claims, normalized. Empty without an
 * {@link OrganizationDomainStore}: no claim, no domain authority.
 *
 * @since 0.1.0
 * @category getters
 */
export const verifiedDomains = (
  domains: typeof OrganizationDomainStore.Service | undefined,
  organizationId: string,
): Effect.Effect<ReadonlyArray<string>, AuthError> =>
  domains === undefined
    ? Effect.succeed([])
    : Effect.map(domains.listByOrganization(organizationId), (claims) =>
        Arr.map(
          Arr.filter(claims, (claim) => claim.verificationState === "verified"),
          (claim) => claim.domain.trim().toLowerCase(),
        ),
      );

/**
 * Whether `organizationId` manages `user`: one of that organization's
 * connections created the user ({@link provisionedBy}), or the user's primary
 * email (the earliest verified one) is on one of its verified domains.
 *
 * @since 0.1.0
 * @category predicates
 */
export const isManagedBy = (input: {
  readonly user: Types.User;
  readonly identifiers: ReadonlyArray<Identifier>;
  readonly organizationId: string;
  readonly verifiedDomains: ReadonlyArray<string>;
}): boolean => {
  if (stampedBy(input.user, input.organizationId)) return true;
  return Option.exists(primaryEmail(input.identifiers), (primary) =>
    isOnDomains(primary.value, input.verifiedDomains),
  );
};

/**
 * {@link isManagedBy} with its reads: the user's identifiers and the
 * organization's verified domains.
 *
 * @since 0.1.0
 * @category predicates
 */
export const isManagedUser = (
  stores: {
    readonly identifiers: {
      readonly listByUser: (userId: string) => Effect.Effect<ReadonlyArray<Identifier>, AuthError>;
    };
    readonly domains: typeof OrganizationDomainStore.Service | undefined;
  },
  organizationId: string,
  user: Types.User,
): Effect.Effect<boolean, AuthError> =>
  Effect.gen(function* () {
    if (stampedBy(user, organizationId)) return true;
    const identifiers = yield* stores.identifiers.listByUser(user.id);
    const domains = yield* verifiedDomains(stores.domains, organizationId);
    return isManagedBy({ user, identifiers, organizationId, verifiedDomains: domains });
  });
