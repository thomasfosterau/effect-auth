# Account linking policy

effect-auth ships an `AccountLinkingPolicy` service that resolves what `handleCallback` does when
an OAuth sign-in matches an existing User by email. The toolkit's defaults are deliberately
conservative — the security cost of getting linking wrong (account takeover via a provider that
issues unverified email claims) is much higher than the UX cost of asking a user to link
explicitly.

## Defaults

- `trustedProviders: []` — empty out of the box. Auto-link happens only for providers a deployer
  explicitly opts in (e.g. `['google', 'microsoft', 'apple']`, documented in the README as a
  recommended starter set). We do not ship trust-list defaults; what counts as "verifies emails"
  is a deployment-context judgement, and a provider's policy can change.
- `linkOnVerifiedEmailMatch: false` — one-line shortcut to "auto-link any provider whose
  emailVerified claim is true on both sides." Off by default; flip to `true` for
  better-auth-equivalent behaviour.
- `allowMultiplePerProvider: false` — one Account per provider per User. Multiples are
  configurable for power deployments (personal + work Google).
- `preventLastCredentialUnlink: true` — `unlinkAccount`, `deletePasskey`, and `deleteApiKey`
  return a structured error if the operation would leave the User with zero primary Credentials.
  Counts across all three primary-Credential entities, not just Account.

We deliberately do not offer an "auto-link on any email match" option. Trusting a provider's
`email` claim without verification is a takeover vector and offering it as a config value invites
deployments to enable it accidentally.

## Sign-in resolution

`handleCallback` returns a discriminated `SignInResolution` rather than the existing
`{ isNewUser }` shape:

- `SignInExisting` — User identified by an Account on this provider, or auto-linked under the
  current policy.
- `CreateNewUser` — no matching User; caller creates one and links the Account.
- `LinkableToExistingUser` — verified-email match on a different provider, but the trust policy
  did not auto-link. Caller prompts the user, forces sign-in to the existing account first, or
  treats as collision — the toolkit does not make that UX decision.
- `Blocked` — the provider account is already linked to a _different_ User (genuine collision /
  potential takeover attempt). Never auto-resolved.

The trade-off: callers handle more shapes than they did before, and the `LinkableToExistingUser`
case forces them to think about a flow they could previously ignore. We accept this because the
alternative is the library silently making security-relevant policy decisions on behalf of
deployments that may not realise it.
