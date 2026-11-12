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
 * parameters, which is why this module calls the ABI itself. Planned
 * follow-up: `@thomasfosterau/argon2` is being asked for a cost-parameter
 * API; with it the adapter depends on that package at runtime again
 * (ADR-0022) and this module's ABI calls and `WasmBinary.ts` go.
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

/** Overwrite `[pointer, pointer + length)` of the instance's memory with zeros. */
const wipe = (instance: Argon2Exports, [pointer, length]: Input): void => {
  new Uint8Array(instance.memory.buffer, pointer, length).fill(0);
};

/**
 * Run `call` with `first` and `second` copied into module memory.
 *
 * Memory: on success both inputs are zeroed and then freed (the password
 * never outlives the call in linear memory), and the JS-side copies of the
 * inputs are zeroed too. A trap (an allocation failure aborts the Rust side)
 * is the failure: it can leave the allocator mid-update, so the whole of the
 * old instance's memory is zeroed and the instance replaced. Instantiating an
 * already-compiled module generates no code, so workerd allows it inside a
 * request (`Workerd.test.ts`). What the crate allocates itself (the
 * `memoryCost` KiB of Argon2 blocks, its BLAKE2b state) is freed without
 * zeroing, because `@thomasfosterau/argon2` builds `argon2` without its
 * `zeroize` feature; the next call reuses and overwrites that memory.
 *
 * Concurrency: everything from the first `alloc` to the last `dealloc` is
 * synchronous, with no `await` or yield in between, and a JS isolate runs one
 * call stack at a time, so two hashes or verifies never interleave inside the
 * one instance, however many fibers run them (`Wasm.test.ts`).
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
    try: () => {
      const a = write(first);
      const b = write(second);
      const value = call(instance, a, b);
      wipe(instance, a);
      wipe(instance, b);
      instance.dealloc(...a);
      instance.dealloc(...b);
      return value;
    },
    catch: (cause) => new KernelError({ reason: "trapped", cause }),
  });
  first.fill(0);
  second.fill(0);
  if (Result.isFailure(result)) {
    new Uint8Array(instance.memory.buffer).fill(0);
    current = instantiate();
  }
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
      // A copy: `withInputs` zeroes its inputs, and the salt is the caller's.
      salt.slice(),
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
        if (length < 0) return Result.fail(new KernelError({ reason: "rejected" }));
        // The PHC string stays allocated in the crate until the next `hash`;
        // zero it once it is copied out.
        const output: Input = [instance.last_ptr(), length];
        const phc = decoder.decode(new Uint8Array(instance.memory.buffer, ...output).slice());
        wipe(instance, output);
        return Result.succeed(phc);
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
      return result === 1 ? "match" : result === 0 ? "mismatch" : "unverifiable";
    },
  );
