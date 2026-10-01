---
"@thomasfosterau/effect-auth": patch
---

Tighten the empty encryption-secret check introduced with the rc.118 move (#252).

- A secret that is present but **whitespace-only** (for example `"   "` or a lone newline) now fails `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with the same "set but empty" `ConfigError` as `""`. A secret with surrounding spaces but non-space content is still accepted, unchanged and untrimmed. An unset variable still leaves encryption off.
- Fix a false "set but empty" when the secret is unset but variables whose names extend it with numeric suffixes (`TWO_FACTOR_ENCRYPT_SECRET_0`, `_1`) are set; they are now treated as sharing the prefix.
