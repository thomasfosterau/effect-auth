/**
 * EIP-191 `personal_sign` signature verification for effect-auth's SIWE
 * module, backed by `@noble/curves` secp256k1 public-key recovery and
 * `@noble/hashes` keccak256.
 *
 * Implements the {@link SiweVerifier} interface from `effect-auth`: recover
 * the signer's public key from the 65-byte `r || s || v` signature over the
 * EIP-191 envelope of the message, derive the Ethereum address
 * (`keccak256(pubkey)[12:]`), and compare it (case-insensitively) to the
 * address claimed in the message.
 */
import { Effect, Layer } from "effect";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { SiweError, SiweVerifierTag, type SiweVerifier } from "effect-auth";

const strip0x = (hex: string): string => (hex.startsWith("0x") ? hex.slice(2) : hex);

const hexToBytes = (hex: string): Uint8Array => {
  const clean = strip0x(hex);
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error("Invalid hex string");
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** keccak256 of the EIP-191 `personal_sign` envelope of a UTF-8 message. */
export const hashPersonalMessage = (message: string): Uint8Array => {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const enveloped = new Uint8Array(prefix.length + body.length);
  enveloped.set(prefix, 0);
  enveloped.set(body, prefix.length);
  return keccak_256(enveloped);
};

/** Derive the `0x`-prefixed lowercase address of an uncompressed public key. */
const addressOfPublicKey = (uncompressed: Uint8Array): string =>
  `0x${bytesToHex(keccak_256(uncompressed.slice(1)).slice(-20))}`;

/**
 * Recover the signing address of an EIP-191 `personal_sign` signature
 * (65-byte `r || s || v` hex). Returns the `0x`-prefixed lowercase address.
 */
export const recoverPersonalSignatureAddress = (input: {
  readonly message: string;
  readonly signature: string;
}): string => {
  const bytes = hexToBytes(input.signature);
  if (bytes.length !== 65) {
    throw new Error("Signature must be 65 bytes (r || s || v)");
  }
  const v = bytes[64]!;
  const recovery = v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) {
    throw new Error(`Invalid recovery id: ${v}`);
  }
  const signature = secp256k1.Signature.fromCompact(bytes.slice(0, 64)).addRecoveryBit(recovery);
  const publicKey = signature.recoverPublicKey(hashPersonalMessage(input.message));
  return addressOfPublicKey(publicKey.toRawBytes(false));
};

/** Build the secp256k1-backed {@link SiweVerifier}. */
export const makeSiweVerifier = (): SiweVerifier => ({
  verifyMessage: (input) =>
    Effect.try({
      try: () => recoverPersonalSignatureAddress(input) === input.address.toLowerCase(),
      catch: (cause) => new SiweError({ message: "Failed to verify SIWE signature", cause }),
    }),
});

/** Layer providing the verifier under effect-auth's `SiweVerifierTag`. */
export const SiweVerifierLayer = Layer.succeed(SiweVerifierTag)(makeSiweVerifier());
