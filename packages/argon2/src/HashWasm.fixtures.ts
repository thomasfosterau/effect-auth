/**
 * PHC strings written by `hash-wasm` 4.13.0, the backend this package used
 * through 0.1.x (#744). Each was generated once by calling hash-wasm's
 * `argon2id` / `argon2i` / `argon2d` with a fixed ASCII salt and
 * `outputType: "encoded"`, and committed so the tests prove those stored
 * hashes still verify, and that the new kernel derives the same strings,
 * without keeping hash-wasm installed. Test-only: excluded from the build.
 */
export interface HashWasmFixture {
  readonly label: string;
  readonly password: string;
  /** The salt hash-wasm was given, as ASCII. */
  readonly salt: string;
  /**
   * Whether the kernel's `hash` can re-derive this string: argon2id, v=19,
   * 32-byte digest. The rest exercise `verify` only.
   */
  readonly derivable: boolean;
  readonly hash: string;
}

export const hashWasmFixtures: ReadonlyArray<HashWasmFixture> = [
  {
    label: "argon2id, default profile (m=19456, t=2, p=1)",
    password: "correct horse battery staple",
    salt: "0123456789abcdef",
    derivable: true,
    hash: "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$gy5SuVm5Z7Vw7keB9se9p87QGcomaseB/S2U1OhTsM0",
  },
  {
    label: "argon2id, server profile (m=65536, t=3, p=1)",
    password: "correct horse battery staple",
    salt: "fedcba9876543210",
    derivable: true,
    hash: "$argon2id$v=19$m=65536,t=3,p=1$ZmVkY2JhOTg3NjU0MzIxMA$uEmsewxnaQTGDj/h0Fub02DxtYOJPIrDerc5o8FkN/g",
  },
  {
    label: "argon2id, p=2, non-ASCII password",
    password: "pässwörd ✓ unicode",
    salt: "unicodeunicodeun",
    derivable: true,
    hash: "$argon2id$v=19$m=1024,t=3,p=2$dW5pY29kZXVuaWNvZGV1bg$ArA6wUYDEk3sakY9qcDxHKIPxwiuTCC14H0jPDlt1gQ",
  },
  {
    label: "argon2id, p=2, 24-byte digest, 32-byte salt",
    password: "pässwörd ✓ unicode",
    salt: "0123456789abcdef0123456789abcdef",
    derivable: false,
    hash: "$argon2id$v=19$m=1024,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY$NLXH3ZRWxhs7m+cua/TKcdSN0IuN1va/",
  },
  {
    label: "argon2id, 64-byte digest",
    password: "x",
    salt: "abcdefghijklmnop",
    derivable: false,
    hash: "$argon2id$v=19$m=512,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$v8f1zungZIxOiVMpZTtXo7oBSR0XYkXoZeFwBXRlXhj5vInkeyzMQXJmS/lrClT5SQxsH7+YSEoa/qnHFGnYPA",
  },
  {
    label: "argon2i (m=4096, t=3, p=1)",
    password: "correct horse battery staple",
    salt: "saltsaltsaltsalt",
    derivable: false,
    hash: "$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$VBRqg4+btGy7IwGibYuU9f0M9kmWU0rIiVedJHJJyHI",
  },
  {
    label: "argon2d (m=4096, t=2, p=1)",
    password: "correct horse battery staple",
    salt: "pepperpepperpepp",
    derivable: false,
    hash: "$argon2d$v=19$m=4096,t=2,p=1$cGVwcGVycGVwcGVycGVwcA$eLc5bttLqmDpW5dfz9k3R3sEWIKW0YqaP3VURUO/n1Y",
  },
];
