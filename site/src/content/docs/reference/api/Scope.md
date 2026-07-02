---
title: "Scope"
description: "API reference for the Scope module."
---

## Scope overview

OAuth-style scope helpers.

OAuth 2.0 access tokens carry a space-delimited list of granted scopes (for
example `"read:user write:repo"`). These utilities parse and check such
scopes for authorization decisions. The boolean helpers accept granted scopes
either as a raw space-delimited string or as any iterable of scope strings.

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [formatScopes](#formatscopes)
  - [hasAllScopes](#hasallscopes)
  - [hasAnyScope](#hasanyscope)
  - [hasScope](#hasscope)
  - [parseScopes](#parsescopes)
  - [requireAllScopes](#requireallscopes)
  - [requireScope](#requirescope)

---

# utils

## formatScopes

Format an iterable of scopes into a single space-delimited string.

**Signature**

```ts
export declare const formatScopes: (scopes: Iterable<string>) => string;
```

## hasAllScopes

Check whether the granted scopes include _all_ of the required scopes.

**Signature**

```ts
export declare const hasAllScopes: (
  granted: string | Iterable<string>,
  required: Iterable<string>,
) => boolean;
```

## hasAnyScope

Check whether the granted scopes include _at least one_ of the required
scopes.

**Signature**

```ts
export declare const hasAnyScope: (
  granted: string | Iterable<string>,
  required: Iterable<string>,
) => boolean;
```

## hasScope

Check whether the granted scopes include the required scope.

**Signature**

```ts
export declare const hasScope: (granted: string | Iterable<string>, required: string) => boolean;
```

## parseScopes

Parse a space-delimited scope string into an array of scopes, dropping empty
entries. Splitting on any run of whitespace tolerates extra spaces.

**Signature**

```ts
export declare const parseScopes: (scope: string) => readonly string[];
```

## requireAllScopes

Require all of the given scopes, failing with `InsufficientScopeError` listing
the missing scopes if any are not granted.

**Signature**

```ts
export declare const requireAllScopes: (
  granted: string | Iterable<string>,
  required: Iterable<string>,
) => Effect.Effect<void, Errors.InsufficientScopeError>;
```

## requireScope

Require a single scope, failing with `InsufficientScopeError` if it is not
granted.

**Signature**

```ts
export declare const requireScope: (
  granted: string | Iterable<string>,
  required: string,
) => Effect.Effect<void, Errors.InsufficientScopeError>;
```
