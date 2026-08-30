/**
 * Security regression tests for the SAML verifier.
 *
 * Each case here reproduces a *shape* of attack that has actually been used
 * against SAML SPs — an unsigned response, a second assertion smuggled beside a
 * signed one (the samlify CVE-2025-47949 shape), a signature that verifies over
 * a decoy element carrying a duplicated `ID` (the node-saml CVE-2025-54369
 * shape), a mis-addressed or expired bearer assertion, a foreign signing key.
 * They are written against the verifier's public surface so they keep their
 * meaning if the implementation is swapped out from under them.
 *
 * Fixtures are signed in-process with a throwaway RSA key. The "certificate" is
 * an SPKI public-key PEM rather than an X.509 certificate: node-saml normalises
 * any PEM label, and xml-crypto hands the value straight to
 * `crypto.createVerify().verify()`, which reads a public key out of either. It
 * keeps the fixtures to `node:crypto` with no certificate-authoring dependency,
 * and exercises exactly the code path a real certificate would.
 */
import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import { generateKeyPairSync } from "node:crypto";
import { SignedXml } from "xml-crypto";
import { SAMLError, type SAMLVerifyInput } from "@thomasfosterau/effect-auth";
import { verifier } from "./index.ts";

const IDP = "https://idp.acme.test/metadata";
const SP = "https://app.test/saml/metadata";
const ACS = "https://app.test/api/auth/sso/saml/acs";
const SSO_URL = "https://idp.acme.test/sso";
const REQUEST_ID = "_req00000000000000000000000000000001";

const keyPair = () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
};

const trusted = keyPair();
const foreign = keyPair();

const iso = (offsetMs: number): string => new Date(Date.now() + offsetMs).toISOString();

interface ResponseOptions {
  readonly audience?: string;
  readonly recipient?: string;
  readonly destination?: string;
  readonly issuer?: string;
  readonly notOnOrAfter?: string;
  readonly notBefore?: string;
  readonly inResponseTo?: string;
  readonly assertionId?: string;
  readonly nameId?: string;
}

/** One `<saml:Assertion>`, with every field a test might want to poison. */
const assertionXml = (
  o: ResponseOptions = {},
): string => `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${o.assertionId ?? "_assertion0000000000000000000001"}" Version="2.0" IssueInstant="${iso(-1000)}">
    <saml:Issuer>${o.issuer ?? IDP}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${o.nameId ?? "worker@acme.test"}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${o.notOnOrAfter ?? iso(5 * 60_000)}" Recipient="${o.recipient ?? ACS}" InResponseTo="${o.inResponseTo ?? REQUEST_ID}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${o.notBefore ?? iso(-60_000)}" NotOnOrAfter="${o.notOnOrAfter ?? iso(5 * 60_000)}">
      <saml:AudienceRestriction><saml:Audience>${o.audience ?? SP}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${iso(-1000)}" SessionIndex="_session0001">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="displayName"><saml:AttributeValue>Worker Bee</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>eng</saml:AttributeValue><saml:AttributeValue>oncall</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>`;

const responseXml = (body: string, o: ResponseOptions = {}): string =>
  `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response00000000000000000000001" Version="2.0" IssueInstant="${iso(-1000)}" Destination="${o.destination ?? ACS}" InResponseTo="${o.inResponseTo ?? REQUEST_ID}">
  <saml:Issuer>${o.issuer ?? IDP}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  ${body}
</samlp:Response>`;

const SIG_ALG = {
  sha256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  sha1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
} as const;
const DIGEST_ALG = {
  sha256: "http://www.w3.org/2001/04/xmlenc#sha256",
  sha1: "http://www.w3.org/2000/09/xmldsig#sha1",
} as const;

/** Sign the element the xpath selects, enveloping the signature inside it. */
const sign = (
  xml: string,
  xpath: string,
  options: { readonly privateKey?: string; readonly alg?: "sha256" | "sha1" } = {},
): string => {
  const alg = options.alg ?? "sha256";
  const sig = new SignedXml({
    privateKey: options.privateKey ?? trusted.privatePem,
    signatureAlgorithm: SIG_ALG[alg],
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });
  sig.addReference({
    xpath,
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: DIGEST_ALG[alg],
  });
  sig.computeSignature(xml, { location: { reference: xpath, action: "append" } });
  return sig.getSignedXml();
};

const ASSERTION_XPATH = "//*[local-name(.)='Assertion']";

/** A well-formed, correctly signed response — the control for every test. */
const validResponse = (o: ResponseOptions = {}): string =>
  sign(responseXml(assertionXml(o), o), ASSERTION_XPATH);

const encode = (xml: string): string => Buffer.from(xml, "utf8").toString("base64");

const input = (xml: string, overrides: Partial<SAMLVerifyInput> = {}): SAMLVerifyInput => ({
  samlResponse: encode(xml),
  idpCertificates: [trusted.publicPem],
  idpEntityId: IDP,
  spEntityId: SP,
  acsUrl: ACS,
  ...overrides,
});

const run = <A>(effect: Effect.Effect<A, SAMLError>): Promise<A> => Effect.runPromise(effect);
const flip = (xml: string, overrides: Partial<SAMLVerifyInput> = {}): Promise<SAMLError> =>
  Effect.runPromise(Effect.flip(verifier.verify(input(xml, overrides))));

describe("SAMLVerifier.verify — happy path", () => {
  it("accepts a correctly signed assertion and returns only signed data", async () => {
    const assertion = await run(verifier.verify(input(validResponse())));

    expect(assertion.issuer).toBe(IDP);
    expect(assertion.nameId).toBe("worker@acme.test");
    expect(assertion.nameIdFormat).toContain("emailAddress");
    expect(assertion.email).toBe("worker@acme.test");
    expect(assertion.displayName).toBe("Worker Bee");
    expect(assertion.attributes["groups"]).toEqual(["eng", "oncall"]);
    expect(assertion.sessionIndex).toBe("_session0001");
    expect(assertion.inResponseTo).toBe(REQUEST_ID);
    expect(assertion.id).toBe("_assertion0000000000000000000001");
    expect(assertion.notOnOrAfter).toBeGreaterThan(Date.now());
  });

  it("honours expectedInResponseTo when the caller supplies one", async () => {
    await run(verifier.verify(input(validResponse(), { expectedInResponseTo: REQUEST_ID })));
    const err = await flip(validResponse(), { expectedInResponseTo: "_someOtherRequest" });
    expect(err.message).toMatch(/does not answer the expected AuthnRequest/);
  });
});

describe("SAMLVerifier.verify — signature scope", () => {
  // (a) The most basic forgery: no signature at all.
  it("rejects an unsigned response", async () => {
    const err = await flip(responseXml(assertionXml()));
    expect(err).toBeInstanceOf(SAMLError);
    expect(err.message).toMatch(/signature/i);
  });

  // (b) samlify CVE-2025-47949 shape: a signed assertion the SP is meant to
  // trust, plus an unsigned one the SP is meant to read. Any response with more
  // than one assertion is invalid, so there is nothing to get confused about.
  it("rejects a second, unsigned assertion smuggled beside a signed one", async () => {
    const signed = sign(responseXml(assertionXml()), ASSERTION_XPATH);
    const forged = assertionXml({
      assertionId: "_assertion0000000000000000000002",
      nameId: "admin@acme.test",
    });
    // Splice the decoy in after the signed assertion, leaving the signature and
    // the bytes it covers untouched.
    const smuggled = signed.replace("</samlp:Response>", `${forged}</samlp:Response>`);

    const err = await flip(smuggled);
    expect(err.message).toMatch(/multiple assertions|signature/i);
  });

  // (c) node-saml CVE-2025-54369 shape: a valid signature over a decoy element
  // that carries the same ID as the assertion the SP would otherwise read.
  // Data must come from the verified element only.
  it("rejects a duplicated ID pointing at a decoy element", async () => {
    const signed = sign(responseXml(assertionXml()), ASSERTION_XPATH);
    // Re-use the signed assertion's ID on a sibling the signature never covered.
    const decoy = `<saml:Advice xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion0000000000000000000001"><saml:NameID>admin@acme.test</saml:NameID></saml:Advice>`;
    const duplicated = signed.replace("</samlp:Response>", `${decoy}</samlp:Response>`);

    const err = await flip(duplicated);
    expect(err.message).toMatch(/ID cannot refer to more than one element|signature/i);
  });

  // (g) The signature verifies — against the wrong key.
  it("rejects an assertion signed by a key this connection does not pin", async () => {
    const err = await flip(
      sign(responseXml(assertionXml()), ASSERTION_XPATH, {
        privateKey: foreign.privatePem,
      }),
    );
    expect(err.message).toMatch(/signature/i);
  });

  it("accepts any pinned certificate, so IdP key rotation needs no downtime", async () => {
    const assertion = await run(
      verifier.verify(
        input(
          sign(responseXml(assertionXml()), ASSERTION_XPATH, { privateKey: foreign.privatePem }),
          {
            idpCertificates: [trusted.publicPem, foreign.publicPem],
          },
        ),
      ),
    );
    expect(assertion.nameId).toBe("worker@acme.test");
  });

  it("refuses to run with no pinned certificate at all", async () => {
    const err = await flip(validResponse(), { idpCertificates: [] });
    expect(err.message).toMatch(/nothing to verify against/);
  });
});

describe("SAMLVerifier.verify — addressing and validity", () => {
  // (d)
  it("rejects an assertion audienced at a different SP", async () => {
    const err = await flip(validResponse({ audience: "https://someone-else.test/metadata" }));
    expect(err.message).toMatch(/audience/i);
  });

  // (f)
  it("rejects a bearer assertion addressed to another ACS URL", async () => {
    const err = await flip(validResponse({ recipient: "https://evil.test/acs" }));
    expect(err.message).toMatch(/issued for/i);
  });

  it("rejects a response whose Destination is not this ACS URL", async () => {
    const err = await flip(validResponse({ destination: "https://evil.test/acs" }));
    expect(err.message).toMatch(/Destination/i);
  });

  // (e)
  it("rejects an expired assertion", async () => {
    const err = await flip(validResponse({ notOnOrAfter: iso(-10 * 60_000) }));
    expect(err.message).toMatch(/expired/i);
  });

  it("rejects an assertion that is not yet valid", async () => {
    const err = await flip(validResponse({ notBefore: iso(10 * 60_000) }));
    expect(err.message).toMatch(/not yet valid/i);
  });

  it("honours the clock-skew window at both edges", async () => {
    // Just outside the default 3-minute window, then inside a widened one.
    const justExpired = validResponse({ notOnOrAfter: iso(-4 * 60_000) });
    expect((await flip(justExpired)).message).toMatch(/expired/i);
    const assertion = await run(verifier.verify(input(justExpired, { clockSkewMs: 10 * 60_000 })));
    expect(assertion.nameId).toBe("worker@acme.test");
  });

  it("rejects a foreign issuer", async () => {
    const err = await flip(validResponse({ issuer: "https://evil.test/metadata" }));
    expect(err.message).toMatch(/issuer/i);
  });

  it("rejects a response whose InResponseTo disagrees with the signed assertion", async () => {
    // The Response attribute sits outside the signature, so rewriting it is
    // free for an attacker — and must not go unnoticed.
    const tampered = validResponse().replace(
      `InResponseTo="${REQUEST_ID}">`,
      `InResponseTo="_someOtherRequest">`,
    );
    const err = await flip(tampered);
    expect(err.message).toMatch(/InResponseTo disagrees/);
  });
});

describe("SAMLVerifier.verify — algorithms and encryption", () => {
  it("rejects SHA-1 signatures by default", async () => {
    const err = await flip(sign(responseXml(assertionXml()), ASSERTION_XPATH, { alg: "sha1" }));
    expect(err.message).toMatch(/weaker than the configured minimum/);
  });

  it("accepts SHA-1 only when a deployment explicitly opts in", async () => {
    const assertion = await run(
      verifier.verify(
        input(sign(responseXml(assertionXml()), ASSERTION_XPATH, { alg: "sha1" }), {
          allowedSignatureAlgorithms: ["sha1"],
        }),
      ),
    );
    expect(assertion.nameId).toBe("worker@acme.test");
  });

  it("refuses HMAC signature methods at any strength", async () => {
    const hmac = validResponse().replace(
      SIG_ALG.sha256,
      "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    );
    const err = await flip(hmac);
    expect(err.message).toMatch(/HMAC/);
  });

  it("rejects an unrecognised signature algorithm rather than shrugging", async () => {
    const weird = validResponse().replace(SIG_ALG.sha256, "http://example.test/my-own-algorithm");
    expect((await flip(weird)).message).toMatch(/Unrecognised/);
  });

  it("rejects encrypted assertions with an actionable message", async () => {
    const encrypted = responseXml(
      `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>`,
    );
    const err = await flip(encrypted);
    expect(err.message).toMatch(/not supported/);
    expect(err.message).toMatch(/signed, unencrypted/);
  });

  it("rejects input that is not a SAML response at all", async () => {
    expect((await flip("not xml at all")).message).toMatch(/did not decode to XML/);
  });
});

describe("SAMLVerifier.buildAuthnRequest", () => {
  it("builds a redirect-binding URL carrying the caller's request id", async () => {
    const request = await run(
      verifier.buildAuthnRequest({
        ssoUrl: SSO_URL,
        spEntityId: SP,
        acsUrl: ACS,
        requestId: REQUEST_ID,
        relayState: "relay-1",
      }),
    );

    expect(request.requestId).toBe(REQUEST_ID);
    const url = new URL(request.url);
    expect(url.origin + url.pathname).toBe(SSO_URL);
    expect(url.searchParams.get("RelayState")).toBe("relay-1");

    // The SAMLRequest is DEFLATE-compressed, base64'd and URL-encoded; inflate
    // it back to prove the id and the SP's identity survived the round trip.
    const { inflateRawSync } = await import("node:zlib");
    const xml = inflateRawSync(
      Buffer.from(url.searchParams.get("SAMLRequest") ?? "", "base64"),
    ).toString("utf8");
    expect(xml).toContain(`ID="${REQUEST_ID}"`);
    expect(xml).toContain(SP);
    expect(xml).toContain(`Destination="${SSO_URL}"`);
    expect(xml).toContain(`AssertionConsumerServiceURL="${ACS}"`);
  });

  it("sets ForceAuthn only when asked", async () => {
    const { inflateRawSync } = await import("node:zlib");
    const inflate = async (forceAuthn: boolean): Promise<string> => {
      const request = await run(
        verifier.buildAuthnRequest({
          ssoUrl: SSO_URL,
          spEntityId: SP,
          acsUrl: ACS,
          requestId: REQUEST_ID,
          forceAuthn,
        }),
      );
      const raw = new URL(request.url).searchParams.get("SAMLRequest") ?? "";
      return inflateRawSync(Buffer.from(raw, "base64")).toString("utf8");
    };
    expect(await inflate(true)).toContain('ForceAuthn="true"');
    expect(await inflate(false)).not.toContain("ForceAuthn");
  });
});

describe("SAMLVerifier.spMetadataXml", () => {
  it("renders an EntityDescriptor the IdP can consume", async () => {
    const xml = await run(verifier.spMetadataXml({ spEntityId: SP, acsUrl: ACS }));
    expect(xml).toContain("<EntityDescriptor");
    expect(xml).toContain(`entityID="${SP}"`);
    expect(xml).toContain(`Location="${ACS}"`);
    expect(xml).toContain('WantAssertionsSigned="true"');
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
  });

  it("can advertise that assertion signatures are not required", async () => {
    const xml = await run(
      verifier.spMetadataXml({ spEntityId: SP, acsUrl: ACS, wantAssertionsSigned: false }),
    );
    expect(xml).not.toContain("WantAssertionsSigned");
  });
});
