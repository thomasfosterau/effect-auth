---
"@thomasfosterau/effect-auth": minor
---

Bound every outbound request and tighten SSO's IdP URLs.

- Every request the core sends (the OAuth and OIDC provider endpoints, SSO discovery, Cloudflare Access's key set, Google One Tap, the captcha and Have I Been Pwned plugins) has a timeout over the whole exchange, body included, and a response-body cap: 10 seconds and 1 MiB by default. Provide the new `OutboundHttp.OutboundLimits` reference to change them. Redirects are no longer followed.
- The OAuth, SSO and One Tap services now cache the JWKS `verifyIdToken` fetches: a token naming an unknown `kid` refetches at most once per 30 seconds, and a failed refetch keeps the keys already held. `RemoteJwksVerifier` keeps `effect/jose`'s own limits, and now asks `fetch` not to follow a redirect from its JWKS URL.
- A provider's error body is logged as a warning excerpt and no longer appears in `OAuthProviderError` or `SsoError` messages.

**Breaking:** SSO connections must use `https` URLs that name no private, loopback, link-local or internal host, checked at registration and before every request. Set the new `SsoConfig.allowPrivateIdpUrls: true` for an IdP on a private network.
