/**
 * The Argon2 kernel: `@thomasfosterau/argon2`'s WebAssembly binary
 * ({@link WASM_BASE64}), compiled **once, at module scope**, and called
 * synchronously through the binary's C ABI.
 *
 * Module scope is the point (#744). workerd forbids generating wasm code while
 * it serves a request (`CompileError: WebAssembly.compile(): Wasm code
 * generation disallowed by embedder`) and allows it only while the worker's
 * modules are evaluated (from compatibility date 2025-06-01, or with
 * `allow_eval_during_startup`), so a backend that compiles lazily on the first
 * hash (as `hash-wasm` does) fails every sign-up and sign-in on a deployed
 * Worker. Don't move the `new WebAssembly.Module` below into a function.
 *
 * The ABI (`src/lib.rs` in `@thomasfosterau/argon2`): the caller `alloc`s
 * linear memory for each input, `hash` writes an argon2id PHC string and
 * returns its length (read from `last_ptr`) or `-1`, and `verify` returns `1`
 * on a match, `0` on a mismatch and `-1` when the stored string cannot be
 * recomputed. `verify` reads the variant (`argon2d`, `argon2i`, `argon2id`),
 * version, costs, salt and digest length from the stored string and compares
 * in constant time (RustCrypto's `subtle`). `hash` always derives argon2id,
 * v=19, with a 32-byte digest. The package's own exports take no cost
 * parameters, which is why this module calls the ABI itself.
 *
 * @module argon2/wasm
 * @internal
 */
import { Data } from "effect";
import * as Arr from "effect/Array";
import * as P from "effect/Predicate";
import * as Result from "effect/Result";
import { WASM_BASE64 } from "./WasmBinary.ts";

interface Argon2Exports {
  readonly memory: WebAssembly.Memory;
  readonly alloc: (length: number) => number;
  readonly dealloc: (pointer: number, length: number) => void;
  readonly hash: (
    passwordPointer: number,
    passwordLength: number,
    saltPointer: number,
    saltLength: number,
    memoryCost: number,
    timeCost: number,
    parallelism: number,
  ) => number;
  readonly last_ptr: () => number;
  readonly verify: (
    passwordPointer: number,
    passwordLength: number,
    storedPointer: number,
    storedLength: number,
  ) => number;
}

const FUNCTIONS = ["alloc", "dealloc", "hash", "last_ptr", "verify"] as const;

/**
 * The instance exports the ABI's memory and functions. Their signatures are
 * fixed by the exact catalog pin, whose bytes `Wasm.test.ts` checks.
 */
const isArgon2Exports = (
  exports: WebAssembly.Exports,
): exports is WebAssembly.Exports & Argon2Exports =>
  exports["memory"] instanceof WebAssembly.Memory &&
  Arr.every(FUNCTIONS, (name) => P.isFunction(exports[name]));

const decodeBase64 = (value: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(atob(value), (char) => char.charCodeAt(0));

// Startup work, not per-request: see the module comment.
const module = new WebAssembly.Module(decodeBase64(WASM_BASE64));

const instantiate = (): Argon2Exports => {
  const { exports } = new WebAssembly.Instance(module, {});
  if (!isArgon2Exports(exports)) {
    throw new TypeError("The embedded Argon2 wasm does not export the expected ABI");
  }
  return exports;
};

let current = instantiate();

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * The kernel could not run: it `"rejected"` the costs or salt (`hash`
 * returned `-1`), or it `"trapped"` (an allocation failure aborts the Rust
 * side). The hasher wraps it in a `HashingError`.
 */
export class KernelError extends Data.TaggedError("KernelError")<{
  readonly reason: "rejected" | "trapped";
  readonly cause?: unknown;
}> {}

/** A buffer copied into module memory: its pointer and length. */
type Input = readonly [pointer: number, length: number];

/**
 * Run `call` with `first` and `second` copied into module memory; `call`
 * frees them. A trap (an allocation failure aborts the Rust side) is the
 * failure, and can leave the allocator mid-update, so the instance is
 * replaced: instantiating an already-compiled module generates no code, so
 * workerd allows it inside a request (`Workerd.test.ts`).
 */
const withInputs = <A>(
  first: Uint8Array,
  second: Uint8Array,
  call: (instance: Argon2Exports, first: Input, second: Input) => A,
): Result.Result<A, KernelError> => {
  const instance = current;
  const write = (bytes: Uint8Array): Input => {
    const pointer = instance.alloc(bytes.length);
    // Read `memory.buffer` after `alloc`: growing memory detaches the old one.
    new Uint8Array(instance.memory.buffer).set(bytes, pointer);
    return [pointer, bytes.length];
  };
  const result = Result.try({
    try: () => call(instance, write(first), write(second)),
    catch: (cause) => new KernelError({ reason: "trapped", cause }),
  });
  if (Result.isFailure(result)) current = instantiate();
  return result;
};

/** Argon2id cost parameters handed to the kernel. */
export interface KernelCosts {
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
}

/**
 * Derive an argon2id (v=19, 32-byte digest) PHC string for `password` and
 * `salt`. Fails when the kernel rejects the parameters or salt, or traps.
 */
export const hashArgon2id = (
  password: string,
  salt: Uint8Array,
  costs: KernelCosts,
): Result.Result<string, KernelError> =>
  Result.flatMap(
    withInputs(
      encoder.encode(password),
      salt,
      (instance, [pw, pwLength], [sp, saltLength]): Result.Result<string, KernelError> => {
        const length = instance.hash(
          pw,
          pwLength,
          sp,
          saltLength,
          costs.memoryCost,
          costs.timeCost,
          costs.parallelism,
        );
        instance.dealloc(pw, pwLength);
        instance.dealloc(sp, saltLength);
        if (length < 0) return Result.fail(new KernelError({ reason: "rejected" }));
        const start = instance.last_ptr();
        const bytes = new Uint8Array(instance.memory.buffer).slice(start, start + length);
        return Result.succeed(decoder.decode(bytes));
      },
    ),
    (outcome) => outcome,
  );

/** What the kernel's `verify` concluded. */
type Verdict = "match" | "mismatch" | "unverifiable";

/**
 * Recompute a stored PHC string for `password`. `"unverifiable"` means the
 * kernel could not recompute it (costs, salt or digest outside the crate's
 * bounds, or malformed encoding). Fails only on a trap.
 */
export const verifyArgon2 = (
  password: string,
  stored: string,
): Result.Result<Verdict, KernelError> =>
  withInputs(
    encoder.encode(password),
    encoder.encode(stored),
    (instance, [pw, pwLength], [hp, hashLength]): Verdict => {
      const result = instance.verify(pw, pwLength, hp, hashLength);
      instance.dealloc(pw, pwLength);
      instance.dealloc(hp, hashLength);
      return result === 1 ? "match" : result === 0 ? "mismatch" : "unverifiable";
    },
  );
