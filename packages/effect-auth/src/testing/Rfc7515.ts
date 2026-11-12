/**
 * RFC 7515 Appendix A.3, "Example JWS Using ECDSA P-256 SHA-256": a static
 * ES256 known-answer vector, copied from the RFC text. Test-only (excluded
 * from the build): `Cipher.test.ts` verifies it in Node and `Workerd.test.ts`
 * inside workerd, so both runtimes check a signature neither produced.
 *
 * @internal
 */

/** The A.3.1 public key (the RFC's JWK without its private `d`). */
export const publicJwk = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
} as const;

/** The A.3.1 compact serialization: `{"alg":"ES256"}` over the A.1 claims. */
export const compactJws =
  "eyJhbGciOiJFUzI1NiJ9" +
  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
  ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
