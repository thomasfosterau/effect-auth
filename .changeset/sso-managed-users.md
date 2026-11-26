---
"@thomasfosterau/effect-auth": minor
---

SSO now signs in only users the connection's organization manages. An asserted email must be on one of the organization's verified domain claims, or belong to a user that organization's SSO provider or SCIM connection created; any other address fails with `SsoError` before an account is created, proved or signed in. A connection without an organization is bound to its own `domain` and to the users it created. Users SSO creates carry a `provisionedBy` stamp (`Auth.ManagedUser.PROVISIONED_BY_ATTRIBUTE`, now one of `SIGN_UP_PROTECTED_ATTRIBUTES`), and `OAuthCreateUserInput` takes optional `attributes` to carry it. The new `Auth.ManagedUser` namespace exports the rule (`isManagedUser`, `isManagedBy`, `verifiedDomains`, `provisionedBy`).

An OIDC connection now requires `email_verified: true`; a profile without the claim is refused unless the connection is registered with `requireEmailVerified: false` (also accepted by `POST /sso-providers`).

Breaking: an organization's SSO connection stops signing in addresses outside its verified domains. Claim and verify the organization's domains before upgrading.
