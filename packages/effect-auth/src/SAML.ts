/**
 * SAML 2.0 contracts — the service-provider (SP) side of an enterprise SSO
 * connection, expressed as tags core can depend on without pulling in an XML
 * stack.
 *
 * Core `effect-auth` depends on nothing but `effect`, and a correct SAML
 * implementation needs XML canonicalisation, XML-DSig verification and DEFLATE
 * — none of which exist in the platform. So this module declares only the
 * **contract**: {@link SAMLVerifier} (parse + cryptographically verify a SAML
 * Response, build an AuthnRequest, render SP metadata) and
 * {@link SAMLReplayStore} (one-time records for AuthnRequest ids and seen
 * assertion ids). {@link module:sso} orchestrates them; the implementation
 * ships separately in `@thomasfosterau/effect-auth-saml`.
 *
 * This is the same split as {@link module:password}'s `PasswordHasher`
 * (contract in core) and `@thomasfosterau/effect-auth-argon2` (implementation).
 *
 * ## What a conforming {@link SAMLVerifier} must enforce
 *
 * Everything below is a *security* requirement, not a nicety. Implementations
 * are expected to reject, not warn:
 *
 * 1. The signature must verify against one of the **pinned**
 *    {@link SAMLVerifyInput.idpCertificates}. Certificates embedded in the
 *    document's `KeyInfo` are never trusted.
 * 2. Profile data must be read **only** from the bytes the signature actually
 *    covers — never from the surrounding, unverified document.
 * 3. A Response carrying more than one `Assertion` (signed or not) is invalid.
 * 4. `wantAssertionsSigned` defaults to `true`; when it is disabled the whole
 *    Response must be signed instead.
 * 5. `Issuer` must equal {@link SAMLVerifyInput.idpEntityId}.
 * 6. `Conditions/AudienceRestriction` must contain
 *    {@link SAMLVerifyInput.spEntityId}.
 * 7. `Destination` and `SubjectConfirmationData/@Recipient` must equal
 *    {@link SAMLVerifyInput.acsUrl}.
 * 8. `NotBefore` / `NotOnOrAfter` must hold, allowing at most
 *    {@link SAMLVerifyInput.clockSkewMs} of skew.
 * 9. `InResponseTo` must equal {@link SAMLVerifyInput.expectedInResponseTo}
 *    when one is supplied.
 * 10. Signature and digest algorithms must be on an allow-list; SHA-1 is off by
 *     default and HMAC methods are never acceptable.
 * 11. Encrypted assertions are rejected outright rather than half-supported.
 *
 * @module saml
 */
import { Context, Data, Effect } from "effect";
import type { AuthError } from "./Errors.ts";

/** Failure to build, parse, or verify a SAML message. */
export class SAMLError extends Data.TaggedError("SAMLError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Digest strength accepted for XML-DSig signature and digest methods, named the
 * way SAML deployments name it. `"sha1"` is listed for the handful of legacy
 * IdPs that still emit it and must be opted into explicitly — it is never part
 * of the default allow-list.
 */
export type SAMLSignatureAlgorithm = "sha1" | "sha256" | "sha512";

/** The default signature/digest allow-list: SHA-256 and stronger. */
export const defaultSignatureAlgorithms: ReadonlyArray<SAMLSignatureAlgorithm> = [
  "sha256",
  "sha512",
];

/** Default tolerance for clock drift between the IdP and this SP: 3 minutes. */
export const defaultClockSkewMs = 3 * 60 * 1000;

/** A SAML Response to verify, together with everything needed to judge it. */
export interface SAMLVerifyInput {
  /**
   * The `SAMLResponse` form field exactly as posted to the ACS endpoint:
   * base64-encoded `<samlp:Response>`. Base64 is the implementation's job so
   * core never has to carry a decoder.
   */
  readonly samlResponse: string;
  /** `RelayState` as received, echoed back on the result for correlation. */
  readonly relayState?: string;
  /**
   * Pinned IdP signing certificates, PEM-encoded. More than one entry supports
   * certificate rotation: any of them may verify the signature.
   */
  readonly idpCertificates: ReadonlyArray<string>;
  /** Expected `Issuer` — the IdP's entity id. */
  readonly idpEntityId: string;
  /** This SP's entity id; must appear in `AudienceRestriction`. */
  readonly spEntityId: string;
  /** This SP's assertion consumer service URL; checked against `Destination`/`Recipient`. */
  readonly acsUrl: string;
  /** AuthnRequest id this response must answer. Omit for IdP-initiated flows. */
  readonly expectedInResponseTo?: string;
  /** Clock-drift tolerance. Default {@link defaultClockSkewMs}. */
  readonly clockSkewMs?: number;
  /** Require a signature over the `Assertion`. Default `true`. */
  readonly wantAssertionsSigned?: boolean;
  /** Require a signature over the whole `Response`. Default `false`. */
  readonly wantAuthnResponseSigned?: boolean;
  /** Accepted signature/digest strengths. Default {@link defaultSignatureAlgorithms}. */
  readonly allowedSignatureAlgorithms?: ReadonlyArray<SAMLSignatureAlgorithm>;
}

/**
 * A verified assertion. Every field here came out of the signed bytes; nothing
 * is carried over from the unverified envelope.
 */
export interface SAMLAssertion {
  /** The `Assertion/@ID`. Use it as the one-time replay key. */
  readonly id: string;
  /** The verified `Issuer`. */
  readonly issuer: string;
  /** `Subject/NameID` — the IdP's identifier for the user. */
  readonly nameId: string;
  /** `Subject/NameID/@Format`, when the IdP set one. */
  readonly nameIdFormat?: string;
  /** Email claim, from an email-format NameID or a recognised attribute. */
  readonly email?: string;
  /** Display name, when the IdP sent one. */
  readonly displayName?: string;
  /** All attribute statements, by attribute name. */
  readonly attributes: Readonly<Record<string, string | ReadonlyArray<string>>>;
  /** `AuthnStatement/@SessionIndex`, needed later for single logout. */
  readonly sessionIndex?: string;
  /** `Response/@InResponseTo`, when the flow was SP-initiated. */
  readonly inResponseTo?: string;
  /** Assertion expiry (epoch ms), for sizing the replay window. */
  readonly notOnOrAfter?: number;
  /** `RelayState` as received. */
  readonly relayState?: string;
}

/** What to put in an `<samlp:AuthnRequest>` and where to send it. */
export interface SAMLAuthnRequestInput {
  /** The IdP's HTTP-Redirect binding SSO endpoint. */
  readonly ssoUrl: string;
  /** This SP's entity id (the request's `Issuer`). */
  readonly spEntityId: string;
  /** This SP's assertion consumer service URL. */
  readonly acsUrl: string;
  /**
   * The id to stamp on the request. Supplied by the caller so it can be
   * persisted (see {@link SAMLReplayStore}) before the user is redirected.
   * Must be a valid XML `NCName` — start it with `_` or a letter.
   */
  readonly requestId: string;
  /** Opaque value the IdP echoes back on the ACS POST. */
  readonly relayState?: string;
  /** Ask the IdP to re-authenticate even if it has a live session. */
  readonly forceAuthn?: boolean;
  /** `NameIDPolicy/@Format`. Defaults to the emailAddress format. */
  readonly nameIdFormat?: string;
}

/** A redirect target for the HTTP-Redirect binding. */
export interface SAMLAuthnRequest {
  /** Fully-formed URL: the SSO endpoint plus `SAMLRequest` (and `RelayState`). */
  readonly url: string;
  /** The `AuthnRequest/@ID`, to match against the response's `InResponseTo`. */
  readonly requestId: string;
}

/** Everything needed to render this SP's `EntityDescriptor`. */
export interface SAMLMetadataInput {
  readonly spEntityId: string;
  readonly acsUrl: string;
  /** Advertise `WantAssertionsSigned`. Default `true`. */
  readonly wantAssertionsSigned?: boolean;
  /** `NameIDFormat` to advertise. Defaults to the emailAddress format. */
  readonly nameIdFormat?: string;
}

/**
 * Parse, verify and generate SAML messages.
 *
 * Core declares this tag; provide it from
 * `@thomasfosterau/effect-auth-saml`'s `layer`. {@link module:sso} resolves it
 * *optionally*, so an app that registers no SAML connections never has to
 * install an XML stack — the SAML paths simply report that support is absent.
 */
export class SAMLVerifier extends Context.Service<
  SAMLVerifier,
  {
    /**
     * Verify a SAML Response against the pinned IdP certificates and the SP's
     * own identity, returning only data covered by the signature.
     */
    readonly verify: (input: SAMLVerifyInput) => Effect.Effect<SAMLAssertion, SAMLError>;
    /** Build an HTTP-Redirect binding `AuthnRequest` URL. */
    readonly buildAuthnRequest: (
      input: SAMLAuthnRequestInput,
    ) => Effect.Effect<SAMLAuthnRequest, SAMLError>;
    /** Render this SP's `EntityDescriptor` XML, for the IdP to consume. */
    readonly spMetadataXml: (input: SAMLMetadataInput) => Effect.Effect<string, SAMLError>;
  }
>()("@effect-auth/SAMLVerifier") {}

/** What a one-time SAML record is guarding against. */
export type SAMLReplayKind =
  /** An `AuthnRequest` id, held until its response comes back. */
  | "authn-request"
  /** An `Assertion` id already consumed, held until the assertion expires. */
  | "assertion";

/** A one-time SAML record. Timestamps are epoch ms. */
export interface SAMLReplayRecord {
  /** The `AuthnRequest/@ID` or `Assertion/@ID`. */
  readonly id: string;
  readonly kind: SAMLReplayKind;
  /** The SSO connection the record belongs to. */
  readonly providerId: string;
  /** `RelayState` minted with an `AuthnRequest`, to match on the way back. */
  readonly relayState?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * One-time storage for SAML ids, keyed by id.
 *
 * Both operations are **atomic** by contract; SAML's replay defences are only
 * as good as that atomicity:
 *
 * - {@link create} is insert-if-absent. It returns `null` — it does *not* fail
 *   — when a record with the same id already exists, and that `null` is exactly
 *   how {@link module:sso} detects a replayed assertion. Implement it as a
 *   single `INSERT ... ON CONFLICT DO NOTHING` (or an equivalent conditional
 *   put), never as a read followed by a write.
 * - {@link consume} is get-and-delete. Two concurrent callers passing the same
 *   id must not both receive the record; the loser gets `null`. Implement it as
 *   a conditional delete returning the deleted row (or a compare-and-swap), the
 *   same way `DeviceAuthorizationStore.claimApproval` does.
 *
 * Expired records may be purged lazily; {@link consume} must treat an expired
 * record as absent.
 */
export class SAMLReplayStore extends Context.Service<
  SAMLReplayStore,
  {
    /** Insert if absent. `null` means the id was already recorded (a replay). */
    readonly create: (
      record: SAMLReplayRecord,
    ) => Effect.Effect<SAMLReplayRecord | null, AuthError>;
    /** Atomically fetch and delete. `null` when unknown or expired. */
    readonly consume: (id: string) => Effect.Effect<SAMLReplayRecord | null, AuthError>;
  }
>()("@effect-auth/SAMLReplayStore") {}

/**
 * In-memory {@link SAMLReplayStore}, backed by a `Map`. Single-process only —
 * good for tests and single-instance deployments; behind a load balancer use a
 * shared store so a replay can't simply land on another instance.
 *
 * Atomicity holds trivially here: JavaScript's single-threaded execution makes
 * each `Effect.sync` body indivisible.
 */
export const memorySAMLReplayStore = (
  records: Map<string, SAMLReplayRecord> = new Map(),
): typeof SAMLReplayStore.Service => ({
  create: (record) =>
    Effect.sync(() => {
      const existing = records.get(record.id);
      if (existing !== undefined && Date.now() <= existing.expiresAt) return null;
      records.set(record.id, record);
      return record;
    }),
  consume: (id) =>
    Effect.sync(() => {
      const existing = records.get(id);
      if (existing === undefined) return null;
      records.delete(id);
      return Date.now() > existing.expiresAt ? null : existing;
    }),
});
