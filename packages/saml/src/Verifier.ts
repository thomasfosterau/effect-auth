/**
 * The {@link SAMLVerifier} implementation: `@node-saml/node-saml` wrapped in an
 * Effect service, plus the checks node-saml deliberately leaves to its caller.
 *
 * @module saml/verifier
 */
import { Effect, Layer } from "effect";
import { SAML, ValidateInResponseTo, generateServiceProviderMetadata } from "@node-saml/node-saml";
import type { Profile } from "@node-saml/node-saml";
import {
  SAMLError,
  SAMLVerifier,
  defaultClockSkewMs,
  defaultSignatureAlgorithms,
  type SAMLAssertion,
  type SAMLAuthnRequest,
  type SAMLAuthnRequestInput,
  type SAMLMetadataInput,
  type SAMLSignatureAlgorithm,
  type SAMLVerifyInput,
} from "@thomasfosterau/effect-auth";

/** The emailAddress NameID format, the sensible default for a B2B SP. */
export const EMAIL_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/**
 * node-saml requires an `idpCert` on every `SAML` instance, including one built
 * only to generate an unsigned `AuthnRequest` — a path that never touches it.
 * Rather than make callers thread certificates into a code path that ignores
 * them, request-only instances get this placeholder. It is never used to make a
 * trust decision: {@link verify} always builds its own instance from the real,
 * pinned certificates.
 */
const REQUEST_ONLY_IDP_CERT = "request-generation-only";

const fail = (message: string, cause?: unknown): Effect.Effect<never, SAMLError> =>
  Effect.fail(new SAMLError({ message, ...(cause !== undefined && { cause }) }));

const messageOf = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

// -----------------------------------------------------------------------------
// Pre-flight checks on the raw document
// -----------------------------------------------------------------------------
//
// These three run against the decoded XML *before* it reaches node-saml, using
// string scans rather than a DOM. That is a deliberate trade: every one of them
// is a *conservative* check — it scans the whole document and rejects if
// anything anywhere fails, including inside unsigned decoy elements an attacker
// controls. The worst an attacker gets from that breadth is a rejected login;
// the alternative (parsing, then trusting the parse to tell signed content from
// unsigned) is the exact confusion these CVEs are made of. It also keeps this
// package's dependency surface to node-saml alone.

/** Elements whose presence means "encrypted", which this version does not support. */
const ENCRYPTED_ELEMENT = /<[A-Za-z0-9_.-]*:?Encrypted(Assertion|ID|Attribute)\b/;

/** Collect the `Algorithm` of every element with the given local name. */
const algorithmsOf = (xml: string, localName: string): ReadonlyArray<string> => {
  const element = new RegExp(`<[A-Za-z0-9_.-]*:?${localName}\\b[^>]*>`, "g");
  const out: string[] = [];
  for (const match of xml.matchAll(element)) {
    const attribute = /\bAlgorithm\s*=\s*("([^"]*)"|'([^']*)')/.exec(match[0]);
    // An element with no parsable Algorithm is recorded as "" so it fails the
    // allow-list below rather than slipping through unexamined.
    out.push(attribute?.[2] ?? attribute?.[3] ?? "");
  }
  return out;
};

/** Digest strength named by an XML-DSig algorithm URI, or `null` if unrecognised. */
const strengthOf = (uri: string): number | null => {
  const match = /sha[-_]?(1|224|256|384|512)\b/i.exec(uri);
  return match === null ? null : Number(match[1]);
};

const namedStrength: Record<SAMLSignatureAlgorithm, number> = { sha1: 1, sha256: 256, sha512: 512 };

/**
 * Reject weak or unacceptable signature/digest methods.
 *
 * The allow-list is expressed as a *floor*: the weakest named algorithm sets
 * the minimum digest strength, so `["sha256", "sha512"]` also accepts SHA-384
 * without anyone having to enumerate every URI the IANA registry will ever
 * hold. HMAC methods are refused outright at any strength — a shared secret is
 * not an identity, and an SP that accepts one can be made to verify a signature
 * it produced itself.
 */
const checkAlgorithms = (
  xml: string,
  allowed: ReadonlyArray<SAMLSignatureAlgorithm>,
): Effect.Effect<void, SAMLError> => {
  const floor = Math.min(...allowed.map((name) => namedStrength[name]));
  for (const localName of ["SignatureMethod", "DigestMethod"]) {
    for (const uri of algorithmsOf(xml, localName)) {
      if (/hmac/i.test(uri)) {
        return fail(`Refusing HMAC ${localName} "${uri}": SAML signatures must be asymmetric`);
      }
      const strength = strengthOf(uri);
      if (strength === null) {
        return fail(`Unrecognised ${localName} algorithm "${uri}"`);
      }
      if (strength < floor) {
        return fail(
          `${localName} "${uri}" is weaker than the configured minimum (${allowed.join(", ")})`,
        );
      }
    }
  }
  return Effect.void;
};

// -----------------------------------------------------------------------------
// Reading the verified assertion
// -----------------------------------------------------------------------------

type XmlNode = { readonly $?: Record<string, string | undefined> } & Record<string, unknown>;

const children = (node: XmlNode | undefined, name: string): ReadonlyArray<XmlNode> => {
  const value = node?.[name];
  return Array.isArray(value) ? (value as ReadonlyArray<XmlNode>) : [];
};

/**
 * xml2js arrays every element except the document root (`explicitRoot`), so a
 * lookup has to cope with both shapes.
 */
const firstChild = (node: XmlNode | undefined, name: string): XmlNode | undefined => {
  const value = node?.[name];
  if (Array.isArray(value)) return value[0] as XmlNode | undefined;
  return typeof value === "object" && value !== null ? (value as XmlNode) : undefined;
};

/** Attribute names IdPs commonly use for an email address. */
const EMAIL_KEYS = [
  "email",
  "emailAddress",
  "mail",
  "urn:oid:0.9.2342.19200300.100.1.3",
  "urn:oid:1.2.840.113549.1.9.1",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
];

/** Attribute names IdPs commonly use for a display name. */
const NAME_KEYS = [
  "displayName",
  "name",
  "cn",
  "urn:oid:2.16.840.1.113730.3.1.241",
  "urn:oid:2.5.4.3",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  "http://schemas.microsoft.com/identity/claims/displayname",
];

/** Narrow node-saml's loose attribute bag to strings and string arrays. */
const normalizeAttributes = (
  raw: unknown,
): Readonly<Record<string, string | ReadonlyArray<string>>> => {
  if (typeof raw !== "object" || raw === null) return {};
  const out: Record<string, string | ReadonlyArray<string>> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value === "string") out[key] = value;
    else if (Array.isArray(value) && value.every((v) => typeof v === "string")) {
      out[key] = value as ReadonlyArray<string>;
    }
  }
  return out;
};

const pick = (
  attributes: Readonly<Record<string, string | ReadonlyArray<string>>>,
  keys: ReadonlyArray<string>,
): string | undefined => {
  for (const key of keys) {
    const value = attributes[key];
    if (typeof value === "string" && value !== "") return value;
    if (Array.isArray(value) && typeof value[0] === "string" && value[0] !== "") return value[0];
  }
  return undefined;
};

const parseInstant = (value: string | undefined): number | undefined => {
  if (value === undefined) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : ms;
};

/**
 * The `SubjectConfirmationData` node-saml leaves for us to police.
 *
 * With `validateInResponseTo: never` — the setting this package uses, because
 * one-time-use is the SSO service's job, not a cache inside a short-lived
 * verifier — node-saml skips the subject-confirmation block wholesale. That
 * block is where `Recipient` lives, so bearer-assertion delivery to the right
 * SP would otherwise go unchecked. Everything read here comes out of the
 * *verified* assertion, so an attacker cannot rewrite it.
 */
interface SubjectConfirmation {
  readonly recipient?: string;
  readonly inResponseTo?: string;
  readonly notOnOrAfter?: number;
}

const readSubjectConfirmation = (assertion: XmlNode): SubjectConfirmation => {
  const subject = firstChild(assertion, "Subject");
  for (const confirmation of children(subject, "SubjectConfirmation")) {
    const data = firstChild(confirmation, "SubjectConfirmationData");
    if (data?.$ === undefined) continue;
    const notOnOrAfter = parseInstant(data.$["NotOnOrAfter"]);
    return {
      ...(data.$["Recipient"] !== undefined && { recipient: data.$["Recipient"] }),
      ...(data.$["InResponseTo"] !== undefined && { inResponseTo: data.$["InResponseTo"] }),
      ...(notOnOrAfter !== undefined && { notOnOrAfter }),
    };
  }
  return {};
};

// -----------------------------------------------------------------------------
// The service
// -----------------------------------------------------------------------------

const verify = (input: SAMLVerifyInput): Effect.Effect<SAMLAssertion, SAMLError> =>
  Effect.gen(function* () {
    if (input.idpCertificates.length === 0) {
      return yield* fail("No IdP certificate configured: there is nothing to verify against");
    }
    const clockSkewMs = input.clockSkewMs ?? defaultClockSkewMs;
    if (clockSkewMs < 0) {
      return yield* fail("clockSkewMs must not be negative (node-saml reads -1 as 'skip checks')");
    }

    const xml = yield* Effect.try({
      try: () => Buffer.from(input.samlResponse, "base64").toString("utf8"),
      catch: (cause) => new SAMLError({ message: "SAMLResponse is not valid base64", cause }),
    });
    if (!xml.includes("<")) {
      return yield* fail("SAMLResponse did not decode to XML");
    }
    if (ENCRYPTED_ELEMENT.test(xml)) {
      return yield* fail(
        "Encrypted SAML assertions are not supported in this version — configure the IdP for signed, unencrypted assertions over TLS",
      );
    }
    yield* checkAlgorithms(xml, input.allowedSignatureAlgorithms ?? defaultSignatureAlgorithms);

    // `wantAssertionsSigned: false` is only tenable when the enclosing Response
    // is signed instead; otherwise nothing in the document is authenticated.
    const wantAssertionsSigned = input.wantAssertionsSigned ?? true;
    const wantAuthnResponseSigned = input.wantAuthnResponseSigned ?? !wantAssertionsSigned;

    const saml = yield* Effect.try({
      try: () =>
        new SAML({
          // Pinned certificates only. node-saml verifies against exactly these;
          // a `KeyInfo` embedded in the document is never consulted.
          idpCert: [...input.idpCertificates],
          idpIssuer: input.idpEntityId,
          issuer: input.spEntityId,
          audience: input.spEntityId,
          callbackUrl: input.acsUrl,
          acceptedClockSkewMs: clockSkewMs,
          wantAssertionsSigned,
          wantAuthnResponseSigned,
          // One-time use is enforced by the SSO service against a shared store;
          // node-saml's in-process cache would be both redundant and, behind a
          // load balancer, wrong.
          validateInResponseTo: ValidateInResponseTo.never,
          identifierFormat: null,
          disableRequestedAuthnContext: true,
        }),
      catch: (cause) =>
        new SAMLError({ message: `Invalid SAML configuration: ${messageOf(cause)}`, cause }),
    });

    const profile = yield* Effect.tryPromise({
      try: async (): Promise<Profile | null> =>
        (
          await saml.validatePostResponseAsync({
            SAMLResponse: input.samlResponse,
          })
        ).profile,
      catch: (cause) =>
        new SAMLError({ message: `SAML response rejected: ${messageOf(cause)}`, cause }),
    });
    if (profile === null) {
      return yield* fail("SAML response carried no assertion");
    }

    const getAssertion = profile.getAssertion;
    if (getAssertion === undefined) {
      return yield* fail("SAML response carried no verified assertion");
    }
    const assertion = firstChild(getAssertion() as XmlNode, "Assertion");
    if (assertion === undefined) {
      return yield* fail("Verified SAML content contained no Assertion");
    }

    const id = assertion.$?.["ID"];
    if (id === undefined || id === "") {
      return yield* fail("SAML assertion has no ID, so it cannot be spent one time only");
    }
    if (profile.issuer !== input.idpEntityId) {
      return yield* fail(
        `SAML issuer "${profile.issuer}" does not match the expected "${input.idpEntityId}"`,
      );
    }

    const confirmation = readSubjectConfirmation(assertion);
    if (confirmation.recipient !== undefined && confirmation.recipient !== input.acsUrl) {
      return yield* fail(
        `SAML assertion was issued for "${confirmation.recipient}", not this SP's ACS URL`,
      );
    }
    if (
      confirmation.notOnOrAfter !== undefined &&
      Date.now() - clockSkewMs >= confirmation.notOnOrAfter
    ) {
      return yield* fail("SAML subject confirmation has expired");
    }

    // `Destination` sits on the Response element, which is only authenticated
    // when the whole response is signed. Checking it regardless costs nothing
    // and closes the endpoint-substitution hole for deployments that do sign.
    for (const match of xml.matchAll(/\bDestination\s*=\s*("([^"]*)"|'([^']*)')/g)) {
      const destination = match[2] ?? match[3] ?? "";
      if (destination !== "" && destination !== input.acsUrl) {
        return yield* fail(`SAML response Destination "${destination}" is not this SP's ACS URL`);
      }
    }

    // Prefer the signed `InResponseTo` over the Response attribute, and reject
    // a document where the two disagree.
    const responseInResponseTo =
      typeof profile["inResponseTo"] === "string" ? profile["inResponseTo"] : undefined;
    if (
      confirmation.inResponseTo !== undefined &&
      responseInResponseTo !== undefined &&
      confirmation.inResponseTo !== responseInResponseTo
    ) {
      return yield* fail("SAML response InResponseTo disagrees with the signed assertion");
    }
    const inResponseTo = confirmation.inResponseTo ?? responseInResponseTo;
    if (input.expectedInResponseTo !== undefined && inResponseTo !== input.expectedInResponseTo) {
      return yield* fail("SAML response does not answer the expected AuthnRequest");
    }

    const attributes = normalizeAttributes(profile["attributes"]);
    // An emailAddress-format NameID *is* the email claim; plenty of IdPs send
    // nothing else. It is inside the signature either way.
    const nameIdEmail =
      profile.nameIDFormat?.endsWith(":emailAddress") === true && profile.nameID.includes("@")
        ? profile.nameID
        : undefined;
    const email = profile.email ?? profile.mail ?? pick(attributes, EMAIL_KEYS) ?? nameIdEmail;
    const displayName = pick(attributes, NAME_KEYS);
    const notOnOrAfter =
      parseInstant(firstChild(assertion, "Conditions")?.$?.["NotOnOrAfter"]) ??
      confirmation.notOnOrAfter;

    return {
      id,
      issuer: profile.issuer,
      nameId: profile.nameID,
      ...(profile.nameIDFormat !== undefined && { nameIdFormat: profile.nameIDFormat }),
      ...(email !== undefined && { email }),
      ...(displayName !== undefined && { displayName }),
      attributes,
      ...(profile.sessionIndex !== undefined && { sessionIndex: profile.sessionIndex }),
      ...(inResponseTo !== undefined && { inResponseTo }),
      ...(notOnOrAfter !== undefined && { notOnOrAfter }),
      ...(input.relayState !== undefined && { relayState: input.relayState }),
    } satisfies SAMLAssertion;
  });

const buildAuthnRequest = (
  input: SAMLAuthnRequestInput,
): Effect.Effect<SAMLAuthnRequest, SAMLError> =>
  Effect.tryPromise({
    try: async (): Promise<SAMLAuthnRequest> => {
      const saml = new SAML({
        idpCert: REQUEST_ONLY_IDP_CERT,
        issuer: input.spEntityId,
        callbackUrl: input.acsUrl,
        entryPoint: input.ssoUrl,
        identifierFormat: input.nameIdFormat ?? EMAIL_NAMEID_FORMAT,
        forceAuthn: input.forceAuthn ?? false,
        // Leave the authentication method to the IdP: an SP that demands
        // PasswordProtectedTransport quietly forbids the IdP's stronger
        // factors, which is the opposite of what an SSO deployment wants.
        disableRequestedAuthnContext: true,
        // The caller minted this id and has already persisted it; node-saml
        // must stamp that exact value so the response can be matched to it.
        generateUniqueId: () => input.requestId,
      });
      const url = await saml.getAuthorizeUrlAsync(input.relayState ?? "", undefined, {});
      return { url, requestId: input.requestId };
    },
    catch: (cause) =>
      new SAMLError({ message: `Failed to build AuthnRequest: ${messageOf(cause)}`, cause }),
  });

const spMetadataXml = (input: SAMLMetadataInput): Effect.Effect<string, SAMLError> =>
  Effect.try({
    try: () =>
      generateServiceProviderMetadata({
        issuer: input.spEntityId,
        callbackUrl: input.acsUrl,
        identifierFormat: input.nameIdFormat ?? EMAIL_NAMEID_FORMAT,
        wantAssertionsSigned: input.wantAssertionsSigned ?? true,
      }),
    catch: (cause) =>
      new SAMLError({ message: `Failed to render SP metadata: ${messageOf(cause)}`, cause }),
  });

/**
 * The verifier, as a plain object. Exposed alongside {@link layer} for the rare
 * call site that wants it without an Effect context — a metadata CLI, say.
 */
export const verifier: typeof SAMLVerifier.Service = {
  verify,
  buildAuthnRequest,
  spMetadataXml,
};

/**
 * A `Layer` providing core's `SAMLVerifier`. Compose it into the layer stack
 * that builds `SSOService` — together with a `SAMLReplayStore` — to turn on
 * SAML connections.
 */
export const layer: Layer.Layer<SAMLVerifier> = Layer.succeed(SAMLVerifier, verifier);
