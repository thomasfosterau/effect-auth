/**
 * Sign-In With Ethereum (SIWE, EIP-4361).
 *
 * The user proves control of an Ethereum account by signing a structured
 * plaintext message (containing a server-issued, single-use nonce) with their
 * wallet. This module owns the protocol pieces that need no cryptography
 * beyond `node:crypto` — nonce issuance, EIP-4361 message construction and
 * parsing, and the sign-in orchestration (find-or-create the user by wallet
 * address, issue a session).
 *
 * The actual signature check (secp256k1 public-key recovery + keccak256)
 * requires a dependency, so — per the hashing-policy precedent — it lives
 * behind the {@link SiweVerifierTag} interface, implemented by the
 * `@effect-auth/siwe` package. Sign-in stays disabled (404 at the HTTP layer)
 * until a verifier layer is provided.
 *
 * User convention: the wallet address is stored lowercase in
 * `user.attributes.walletAddress`.
 *
 * @module siwe
 */
import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import type { AuthError } from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";
import { SessionManagerTag } from "./Session.js";
import type * as Types from "./Types.js";

/** Failure to issue a nonce, parse a message, or complete a SIWE sign-in. */
export class SiweError extends Data.TaggedError("SiweError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

// -----------------------------------------------------------------------------
// EIP-4361 message
// -----------------------------------------------------------------------------

/** A parsed EIP-4361 message. */
export interface SiweMessage {
  /** RFC 3986 authority requesting the signing (e.g. `app.example.com`). */
  readonly domain: string;
  /** `0x`-prefixed Ethereum address performing the signing. */
  readonly address: string;
  /** Human-readable statement shown by the wallet. */
  readonly statement?: string;
  /** RFC 3986 URI referring to the subject of the signing. */
  readonly uri: string;
  readonly version: "1";
  readonly chainId: number;
  /** Server-issued randomized token (from {@link SiweService.generateNonce}). */
  readonly nonce: string;
  /** ISO 8601 datetime of the issuance. */
  readonly issuedAt: string;
  /** ISO 8601 datetime after which the message is invalid. */
  readonly expirationTime?: string;
  /** ISO 8601 datetime before which the message is invalid. */
  readonly notBefore?: string;
  readonly requestId?: string;
  readonly resources?: readonly string[];
}

/** Serialize a {@link SiweMessage} into EIP-4361 plaintext for signing. */
export const formatSiweMessage = (message: SiweMessage): string => {
  const lines: string[] = [
    `${message.domain} wants you to sign in with your Ethereum account:`,
    message.address,
    "",
  ];
  if (message.statement !== undefined) {
    lines.push(message.statement, "");
  }
  lines.push(
    `URI: ${message.uri}`,
    `Version: ${message.version}`,
    `Chain ID: ${message.chainId}`,
    `Nonce: ${message.nonce}`,
    `Issued At: ${message.issuedAt}`,
  );
  if (message.expirationTime !== undefined)
    lines.push(`Expiration Time: ${message.expirationTime}`);
  if (message.notBefore !== undefined) lines.push(`Not Before: ${message.notBefore}`);
  if (message.requestId !== undefined) lines.push(`Request ID: ${message.requestId}`);
  if (message.resources !== undefined && message.resources.length > 0) {
    lines.push("Resources:", ...message.resources.map((r) => `- ${r}`));
  }
  return lines.join("\n");
};

const FIRST_LINE = /^(?<domain>[^\n]+) wants you to sign in with your Ethereum account:$/;

/** Parse EIP-4361 plaintext into a {@link SiweMessage}. */
export const parseSiweMessage = (text: string): Effect.Effect<SiweMessage, SiweError> =>
  Effect.suspend(() => {
    const fail = (message: string) => Effect.fail(new SiweError({ message }));

    const lines = text.split("\n");
    const first = lines[0] === undefined ? undefined : FIRST_LINE.exec(lines[0]);
    const address = lines[1];
    if (!first?.groups?.["domain"] || address === undefined || lines[2] !== "") {
      return fail("Malformed SIWE message: bad preamble");
    }

    // Optional statement: a non-empty block between the blank line after the
    // address and the blank line before the `URI:` field.
    let index = 3;
    let statement: string | undefined;
    if (lines[index] !== undefined && !lines[index]!.startsWith("URI: ")) {
      statement = lines[index];
      index += 1;
      if (lines[index] !== "") return fail("Malformed SIWE message: bad statement block");
      index += 1;
    }

    const fields = new Map<string, string>();
    const resources: string[] = [];
    let inResources = false;
    for (; index < lines.length; index++) {
      const line = lines[index]!;
      if (inResources) {
        if (!line.startsWith("- ")) return fail("Malformed SIWE message: bad resource entry");
        resources.push(line.slice(2));
        continue;
      }
      if (line === "Resources:") {
        inResources = true;
        continue;
      }
      const sep = line.indexOf(": ");
      if (sep < 0) return fail(`Malformed SIWE message: unparseable line "${line}"`);
      fields.set(line.slice(0, sep), line.slice(sep + 2));
    }

    const uri = fields.get("URI");
    const version = fields.get("Version");
    const chainId = Number(fields.get("Chain ID"));
    const nonce = fields.get("Nonce");
    const issuedAt = fields.get("Issued At");
    if (uri === undefined || nonce === undefined || issuedAt === undefined) {
      return fail("Malformed SIWE message: missing required fields");
    }
    if (version !== "1") return fail("Unsupported SIWE version");
    if (!Number.isInteger(chainId)) return fail("Malformed SIWE message: bad chain id");
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
      return fail("Malformed SIWE message: bad address");
    }

    const expirationTime = fields.get("Expiration Time");
    const notBefore = fields.get("Not Before");
    const requestId = fields.get("Request ID");

    return Effect.succeed({
      domain: first.groups["domain"],
      address,
      ...(statement !== undefined && { statement }),
      uri,
      version,
      chainId,
      nonce,
      issuedAt,
      ...(expirationTime !== undefined && { expirationTime }),
      ...(notBefore !== undefined && { notBefore }),
      ...(requestId !== undefined && { requestId }),
      ...(resources.length > 0 && { resources }),
    } satisfies SiweMessage);
  });

// -----------------------------------------------------------------------------
// Stores + verifier
// -----------------------------------------------------------------------------

/** A single-use sign-in nonce. */
export interface SiweNonce {
  readonly nonce: string;
  /** Epoch milliseconds. */
  readonly expiresAt: number;
  readonly createdAt: number;
}

/** Ephemeral store for issued nonces. */
export interface SiweNonceStore {
  readonly create: (nonce: SiweNonce) => Effect.Effect<SiweNonce, AuthError>;
  readonly get: (nonce: string) => Effect.Effect<SiweNonce | null, AuthError>;
  readonly delete: (nonce: string) => Effect.Effect<void, AuthError>;
}

export class SiweNonceStoreTag extends Context.Service<SiweNonceStoreTag, SiweNonceStore>()(
  "@effect-auth/SiweNonceStore",
) {}

// Public ergonomic alias
export const SiweNonceStore = SiweNonceStoreTag;

/**
 * Minimal user store for wallet sign-ins. Implementations look users up by
 * the lowercase wallet address and, on first sign-in, create a user carrying
 * `attributes.walletAddress`.
 */
export interface SiweUserStore {
  readonly getUserByWalletAddress: (
    walletAddress: string,
  ) => Effect.Effect<Types.User | null, AuthError>;
  readonly createUser: (input: {
    readonly walletAddress: string;
  }) => Effect.Effect<Types.User, AuthError>;
}

export class SiweUserStoreTag extends Context.Service<SiweUserStoreTag, SiweUserStore>()(
  "@effect-auth/SiweUserStore",
) {}

// Public ergonomic alias
export const SiweUserStore = SiweUserStoreTag;

/**
 * Signature verification over the EIP-191 `personal_sign` scheme. Implemented
 * by `@effect-auth/siwe` (secp256k1 recovery needs a dependency, which stays
 * out of the core package per the hashing-policy precedent).
 */
export interface SiweVerifier {
  /**
   * `true` when `signature` (65-byte `r || s || v` hex) over the EIP-191
   * envelope of `message` recovers an Ethereum address equal to `address`
   * (case-insensitive).
   */
  readonly verifyMessage: (input: {
    readonly message: string;
    readonly signature: string;
    readonly address: string;
  }) => Effect.Effect<boolean, SiweError>;
}

export class SiweVerifierTag extends Context.Service<SiweVerifierTag, SiweVerifier>()(
  "@effect-auth/SiweVerifier",
) {}

// Public ergonomic alias
export const SiweVerifier = SiweVerifierTag;

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/** Result of a completed SIWE sign-in. */
export interface SiweSignInResult {
  readonly user: Types.User;
  readonly session: Types.Session;
  readonly isNewUser: boolean;
  /** Lowercase wallet address the signature recovered to. */
  readonly walletAddress: string;
}

/** Configuration for {@link makeSiweService}. */
export interface SiweConfig {
  /** RFC 3986 authority that must appear in signed messages (e.g. `app.example.com`). */
  readonly domain: string;
  /** Nonce lifetime in ms (default: 10 minutes). */
  readonly nonceExpiresIn?: number;
}

export interface SiweService {
  /** Issue a single-use nonce for the wallet to embed in its message. */
  readonly generateNonce: () => Effect.Effect<
    { readonly nonce: string; readonly expiresAt: number },
    AuthError,
    SiweNonceStoreTag
  >;

  /**
   * Complete a SIWE sign-in: parse the message, check the domain, redeem the
   * nonce (single use), enforce the message's time window, verify the
   * signature, find-or-create the user by wallet address, and issue a session.
   */
  readonly verify: (input: {
    readonly message: string;
    readonly signature: string;
  }) => Effect.Effect<
    SiweSignInResult,
    SiweError | AuthError | HookError,
    SiweNonceStoreTag | SiweUserStoreTag | SiweVerifierTag | SessionManagerTag | Hooks
  >;
}

export class SiweServiceTag extends Context.Service<SiweServiceTag, SiweService>()(
  "@effect-auth/SiweService",
) {
  /**
   * Construct a Layer providing this service — the canonical form of
   * {@link SiweServiceLayer}.
   */
  static readonly layer = (config: SiweConfig) => SiweServiceLayer(config);
}

// Public ergonomic alias
export const SiweService = SiweServiceTag;

export const makeSiweService = (config: SiweConfig): Effect.Effect<SiweService, never> => {
  const nonceExpiresIn = config.nonceExpiresIn ?? 10 * 60 * 1000;

  return Effect.succeed({
    generateNonce: () =>
      Effect.gen(function* () {
        const store = yield* SiweNonceStoreTag;
        const now = Date.now();
        const record: SiweNonce = {
          // Alphanumeric (EIP-4361 requires 8+ alphanumeric characters).
          nonce: crypto.randomBytes(16).toString("hex"),
          expiresAt: now + nonceExpiresIn,
          createdAt: now,
        };
        yield* store.create(record);
        return { nonce: record.nonce, expiresAt: record.expiresAt };
      }),

    verify: (input) =>
      Effect.gen(function* () {
        const nonceStore = yield* SiweNonceStoreTag;
        const userStore = yield* SiweUserStoreTag;
        const verifier = yield* SiweVerifierTag;
        const sessionManager = yield* SessionManagerTag;

        const message = yield* parseSiweMessage(input.message);

        if (message.domain !== config.domain) {
          return yield* new SiweError({ message: "SIWE domain mismatch" });
        }

        // Nonce: must exist, be unexpired, and is burned on first use.
        const nonce = yield* nonceStore.get(message.nonce);
        if (nonce === null) {
          return yield* new SiweError({ message: "Unknown or already used nonce" });
        }
        yield* nonceStore.delete(nonce.nonce);
        if (Date.now() > nonce.expiresAt) {
          return yield* new SiweError({ message: "Nonce expired" });
        }

        // The message's own validity window.
        const now = Date.now();
        if (message.expirationTime !== undefined && now > Date.parse(message.expirationTime)) {
          return yield* new SiweError({ message: "SIWE message expired" });
        }
        if (message.notBefore !== undefined && now < Date.parse(message.notBefore)) {
          return yield* new SiweError({ message: "SIWE message not yet valid" });
        }

        const valid = yield* verifier.verifyMessage({
          message: input.message,
          signature: input.signature,
          address: message.address,
        });
        if (!valid) {
          return yield* new SiweError({ message: "Invalid SIWE signature" });
        }

        const walletAddress = message.address.toLowerCase();
        let user = yield* userStore.getUserByWalletAddress(walletAddress);
        const isNewUser = user === null;
        if (user === null) {
          user = yield* userStore.createUser({ walletAddress });
        }

        const session = yield* sessionManager.createSession(user.id);
        return { user, session, isNewUser, walletAddress };
      }),
  } satisfies SiweService);
};

export const SiweServiceLayer = (config: SiweConfig) =>
  Layer.effect(SiweServiceTag, makeSiweService(config));
