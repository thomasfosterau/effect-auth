/**
 * Punycode (RFC 3492) decoding of one IDNA label, for `Confusables.ts` to
 * judge a domain label as the Unicode it stands for.
 *
 * @internal
 */
import * as Option from "effect/Option";

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const MAX_CODE_POINT = 0x10ffff;

/** RFC 3492 §6.1. */
const adapt = (delta: number, points: number, first: boolean): number => {
  let d = first ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / points);
  let k = 0;
  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW));
};

/** A basic code point's digit value, or `BASE` for one that is no digit. */
const digitOf = (cp: number): number => {
  if (cp >= 0x30 && cp <= 0x39) return cp - 22;
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41;
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61;
  return BASE;
};

/** The threshold for the digit at `k` (RFC 3492 §6.2). */
const threshold = (k: number, bias: number): number =>
  k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;

/**
 * Read one variable-length integer from `pos`, added to `i`: the new `i` and
 * the position after it, or none when the input ends inside it, holds a
 * non-digit or overflows.
 */
const readDelta = (
  input: string,
  start: number,
  i: number,
  bias: number,
): Option.Option<readonly [number, number]> => {
  let pos = start;
  let value = i;
  let w = 1;
  for (let k = BASE; pos < input.length; k += BASE) {
    const digit = digitOf(input.charCodeAt(pos++));
    if (digit >= BASE) return Option.none();
    value += digit * w;
    const t = threshold(k, bias);
    if (digit < t) return Option.some([value, pos] as const);
    w *= BASE - t;
    if (!Number.isSafeInteger(value) || !Number.isSafeInteger(w)) return Option.none();
  }
  return Option.none();
};

/** The basic code points before the last `-`, or none when one is not basic. */
const basicPrefix = (input: string, delimiter: number): Option.Option<Array<number>> => {
  const output: Array<number> = [];
  for (let at = 0; at < delimiter; at++) {
    const cp = input.charCodeAt(at);
    if (cp >= 0x80) return Option.none();
    output.push(cp);
  }
  return Option.some(output);
};

/**
 * Decode one punycode label body (the part after `xn--`), or none when it is
 * malformed: a non-basic code point before the delimiter, a digit sequence
 * cut short, an overflow or a code point past U+10FFFF.
 */
export const decodePunycode = (input: string): Option.Option<string> => {
  const delimiter = input.lastIndexOf("-");
  const basic = basicPrefix(input, delimiter);
  if (Option.isNone(basic)) return Option.none();
  const output = basic.value;
  let n = 0x80;
  let bias = 72;
  let i = 0;
  let pos = delimiter < 0 ? 0 : delimiter + 1;
  while (pos < input.length) {
    const read = readDelta(input, pos, i, bias);
    if (Option.isNone(read)) return Option.none();
    const [next, after] = read.value;
    const length = output.length + 1;
    bias = adapt(next - i, length, i === 0);
    n += Math.floor(next / length);
    if (n > MAX_CODE_POINT) return Option.none();
    i = next % length;
    output.splice(i, 0, n);
    i++;
    pos = after;
  }
  return Option.some(String.fromCodePoint(...output));
};
