# @effect-auth/siwe

Sign-In With Ethereum (EIP-4361) signature verification for [effect-auth](https://github.com/thomasfosterau/effect-auth), backed by [`@noble/curves`](https://github.com/paulmillr/noble-curves) secp256k1 public-key recovery and `@noble/hashes` keccak256.

The SIWE protocol pieces — nonce issuance, EIP-4361 message construction/parsing, and the sign-in flow — live in `effect-auth`'s `Siwe` module (dependency-free). This package supplies the one piece that needs a dependency: verifying the wallet's EIP-191 `personal_sign` signature. Per effect-auth's hashing policy, dependency-backed crypto ships as its own package.

## Usage

```ts
import { SiweVerifierLayer } from "@effect-auth/siwe";
import { SiweServiceLayer } from "effect-auth";
import { Layer } from "effect";

const siwe = Layer.mergeAll(
  SiweServiceLayer({ domain: "app.example.com" }),
  SiweVerifierLayer,
  // + your SiweNonceStore / SiweUserStore layers
);
```

Provide this alongside your other auth services to `makeAuthWebHandler` and the `POST /siwe/nonce` + `POST /sign-in/siwe` endpoints come alive (they answer 404 until every SIWE service is present).

Users created by wallet sign-in carry the lowercase address in `user.attributes.walletAddress`.

Lower-level helpers are exported too: `recoverPersonalSignatureAddress`, `hashPersonalMessage`, and `makeSiweVerifier`.
