---
title: "HttpApi"
description: "API reference for the HttpApi module."
---

## HttpApi overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AuthApi](#authapi)
  - [authGroup](#authgroup)
  - [getOpenApiSpec](#getopenapispec)

---

# utils

## AuthApi

The complete auth API, annotated with OpenAPI document metadata.

**Signature**

```ts
export declare const AuthApi: HttpApi.HttpApi<
  "AuthApi",
  HttpApiGroup.HttpApiGroup<
    "auth",
    | HttpApiEndpoint.HttpApiEndpoint<
        "signUp",
        "POST",
        "/sign-up",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly email: Schema.String;
            readonly password: Schema.String;
            readonly name: Schema.optional<Schema.String>;
            readonly attributes: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
            readonly captchaToken: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Conflict,
                { readonly message: string; readonly _tag: "Conflict" },
                readonly [Schema.TaggedStruct<"Conflict", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Conflict" }
              >,
              Schema.TaggedStruct<"Conflict", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signIn",
        "POST",
        "/sign-in",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly email: Schema.String;
            readonly password: Schema.String;
            readonly captchaToken: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signOut",
        "POST",
        "/sign-out",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<never>,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "getSession",
        "GET",
        "/session",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly session: Schema.Struct<{
              readonly id: Schema.String;
              readonly userId: Schema.String;
              readonly expiresAt: Schema.Number;
              readonly createdAt: Schema.Number;
              readonly lastActivityAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
          }>
        >,
        HttpApiEndpoint.Json<
          Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "sendVerificationEmail",
        "POST",
        "/email-verification/send",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly email: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "verifyEmail",
        "POST",
        "/email-verification/verify",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "requestPasswordReset",
        "POST",
        "/password-reset/request",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly email: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "resetPassword",
        "POST",
        "/password-reset/reset",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly token: Schema.String; readonly newPassword: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "changePassword",
        "POST",
        "/change-password",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly currentPassword: Schema.String;
            readonly newPassword: Schema.String;
            readonly revokeOtherSessions: Schema.optional<Schema.Boolean>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "updateUser",
        "PATCH",
        "/user",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "listSessions",
        "GET",
        "/sessions",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.$Array<
            Schema.Struct<{
              readonly id: Schema.String;
              readonly userId: Schema.String;
              readonly expiresAt: Schema.Number;
              readonly createdAt: Schema.Number;
              readonly lastActivityAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>
          >
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "revokeSession",
        "DELETE",
        "/sessions/:sessionId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ sessionId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "revokeOtherSessions",
        "POST",
        "/sessions/revoke-others",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "magicLinkSend",
        "POST",
        "/magic-link/send",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly email: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "magicLinkVerify",
        "POST",
        "/magic-link/verify",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "changeEmailRequest",
        "POST",
        "/change-email/request",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly newEmail: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "changeEmailConfirm",
        "POST",
        "/change-email/confirm",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "deleteUserRequest",
        "POST",
        "/delete-user/request",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "deleteUserConfirm",
        "POST",
        "/delete-user/confirm",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "emailOtpSend",
        "POST",
        "/email-otp/send",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly email: Schema.String;
            readonly purpose: Schema.Literals<
              readonly ["sign-in", "email-verification", "forget-password"]
            >;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signInEmailOtp",
        "POST",
        "/sign-in/email-otp",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly email: Schema.String; readonly otp: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signInAnonymous",
        "POST",
        "/sign-in/anonymous",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signInUsername",
        "POST",
        "/sign-in/username",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly username: Schema.String; readonly password: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "multiSessionList",
        "GET",
        "/multi-session/list",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.$Array<
            Schema.Struct<{
              readonly session: Schema.Struct<{
                readonly id: Schema.String;
                readonly userId: Schema.String;
                readonly expiresAt: Schema.Number;
                readonly createdAt: Schema.Number;
                readonly lastActivityAt: Schema.Number;
                readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
              }>;
              readonly user: Schema.Struct<{
                readonly id: Schema.String;
                readonly email: Schema.String;
                readonly emailVerified: Schema.Boolean;
                readonly name: Schema.optional<Schema.String>;
                readonly image: Schema.optional<Schema.String>;
                readonly createdAt: Schema.Number;
                readonly updatedAt: Schema.Number;
                readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
              }>;
            }>
          >
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "multiSessionSetActive",
        "POST",
        "/multi-session/set-active",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly sessionId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "multiSessionRevoke",
        "POST",
        "/multi-session/revoke",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly sessionId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "deviceCode",
        "POST",
        "/device/code",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly clientId: Schema.optional<Schema.String>;
            readonly scopes: Schema.optional<Schema.$Array<Schema.String>>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly deviceCode: Schema.String;
            readonly userCode: Schema.String;
            readonly verificationUri: Schema.String;
            readonly expiresIn: Schema.Number;
            readonly interval: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "deviceToken",
        "POST",
        "/device/token",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly deviceCode: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "deviceApprove",
        "POST",
        "/device/approve",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly userCode: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "deviceDeny",
        "POST",
        "/device/deny",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly userCode: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "phoneOtpSend",
        "POST",
        "/phone-otp/send",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly phoneNumber: Schema.String;
            readonly purpose: Schema.Literals<readonly ["sign-in", "phone-verification"]>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signInPhoneOtp",
        "POST",
        "/sign-in/phone-otp",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly phoneNumber: Schema.String; readonly otp: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "twoFactorEnable",
        "POST",
        "/two-factor/enable",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly password: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly secret: Schema.String;
            readonly totpUri: Schema.String;
            readonly backupCodes: Schema.$Array<Schema.String>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "twoFactorConfirm",
        "POST",
        "/two-factor/confirm",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly code: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "twoFactorDisable",
        "POST",
        "/two-factor/disable",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly password: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "twoFactorRegenerateBackupCodes",
        "POST",
        "/two-factor/regenerate-backup-codes",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly password: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly backupCodes: Schema.$Array<Schema.String> }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "twoFactorVerifyTotp",
        "POST",
        "/two-factor/verify-totp",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly token: Schema.String; readonly code: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "twoFactorVerifyBackupCode",
        "POST",
        "/two-factor/verify-backup-code",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly token: Schema.String; readonly code: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgCreate",
        "POST",
        "/organization/create",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly name: Schema.String;
            readonly slug: Schema.String;
            readonly logo: Schema.optional<Schema.String>;
            readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly name: Schema.String;
            readonly slug: Schema.String;
            readonly logo: Schema.optional<Schema.String>;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgList",
        "GET",
        "/organizations",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.$Array<
            Schema.Struct<{
              readonly id: Schema.String;
              readonly name: Schema.String;
              readonly slug: Schema.String;
              readonly logo: Schema.optional<Schema.String>;
              readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
              readonly createdAt: Schema.Number;
            }>
          >
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgGet",
        "GET",
        "/organization/:organizationId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly organization: Schema.Struct<{
              readonly id: Schema.String;
              readonly name: Schema.String;
              readonly slug: Schema.String;
              readonly logo: Schema.optional<Schema.String>;
              readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
              readonly createdAt: Schema.Number;
            }>;
            readonly members: Schema.$Array<
              Schema.Struct<{
                readonly id: Schema.String;
                readonly organizationId: Schema.String;
                readonly userId: Schema.String;
                readonly role: Schema.String;
                readonly createdAt: Schema.Number;
              }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgUpdate",
        "PATCH",
        "/organization/:organizationId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly name: Schema.optional<Schema.String>;
            readonly slug: Schema.optional<Schema.String>;
            readonly logo: Schema.optional<Schema.String>;
            readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly name: Schema.String;
            readonly slug: Schema.String;
            readonly logo: Schema.optional<Schema.String>;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgDelete",
        "DELETE",
        "/organization/:organizationId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgSetActive",
        "POST",
        "/organization/set-active",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly organizationId: Schema.NullOr<Schema.String> }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgInvite",
        "POST",
        "/organization/:organizationId/invitations",
        HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly email: Schema.String; readonly role: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly organizationId: Schema.String;
            readonly email: Schema.String;
            readonly role: Schema.String;
            readonly status: Schema.Literals<
              readonly ["pending", "accepted", "rejected", "canceled"]
            >;
            readonly inviterId: Schema.String;
            readonly expiresAt: Schema.Number;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgListInvitations",
        "GET",
        "/organization/:organizationId/invitations",
        HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.$Array<
            Schema.Struct<{
              readonly id: Schema.String;
              readonly organizationId: Schema.String;
              readonly email: Schema.String;
              readonly role: Schema.String;
              readonly status: Schema.Literals<
                readonly ["pending", "accepted", "rejected", "canceled"]
              >;
              readonly inviterId: Schema.String;
              readonly expiresAt: Schema.Number;
              readonly createdAt: Schema.Number;
            }>
          >
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgAcceptInvitation",
        "POST",
        "/invitations/:invitationId/accept",
        HttpApiEndpoint.StringTree<Schema.Struct<{ invitationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly organizationId: Schema.String;
            readonly userId: Schema.String;
            readonly role: Schema.String;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgRejectInvitation",
        "POST",
        "/invitations/:invitationId/reject",
        HttpApiEndpoint.StringTree<Schema.Struct<{ invitationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly organizationId: Schema.String;
            readonly email: Schema.String;
            readonly role: Schema.String;
            readonly status: Schema.Literals<
              readonly ["pending", "accepted", "rejected", "canceled"]
            >;
            readonly inviterId: Schema.String;
            readonly expiresAt: Schema.Number;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgCancelInvitation",
        "POST",
        "/invitations/:invitationId/cancel",
        HttpApiEndpoint.StringTree<Schema.Struct<{ invitationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly organizationId: Schema.String;
            readonly email: Schema.String;
            readonly role: Schema.String;
            readonly status: Schema.Literals<
              readonly ["pending", "accepted", "rejected", "canceled"]
            >;
            readonly inviterId: Schema.String;
            readonly expiresAt: Schema.Number;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgAddMember",
        "POST",
        "/organization/:organizationId/members",
        HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly userId: Schema.String; readonly role: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly organizationId: Schema.String;
            readonly userId: Schema.String;
            readonly role: Schema.String;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgUpdateMemberRole",
        "PATCH",
        "/organization/:organizationId/members",
        HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly userId: Schema.String; readonly role: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly organizationId: Schema.String;
            readonly userId: Schema.String;
            readonly role: Schema.String;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "orgRemoveMember",
        "DELETE",
        "/organization/:organizationId/members/:userId",
        HttpApiEndpoint.StringTree<
          Schema.Struct<{ organizationId: Schema.String; userId: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminListUsers",
        "POST",
        "/admin/users/list",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly limit: Schema.optional<Schema.Number>;
            readonly offset: Schema.optional<Schema.Number>;
            readonly searchEmail: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly users: Schema.$Array<
              Schema.Struct<{
                readonly id: Schema.String;
                readonly email: Schema.String;
                readonly emailVerified: Schema.Boolean;
                readonly name: Schema.optional<Schema.String>;
                readonly image: Schema.optional<Schema.String>;
                readonly createdAt: Schema.Number;
                readonly updatedAt: Schema.Number;
                readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
              }>
            >;
            readonly total: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminSetRole",
        "POST",
        "/admin/users/set-role",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly userId: Schema.String; readonly role: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminBanUser",
        "POST",
        "/admin/users/ban",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly userId: Schema.String;
            readonly reason: Schema.optional<Schema.String>;
            readonly expiresIn: Schema.optional<Schema.Number>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminUnbanUser",
        "POST",
        "/admin/users/unban",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminRemoveUser",
        "POST",
        "/admin/users/remove",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminRevokeSessions",
        "POST",
        "/admin/users/revoke-sessions",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminImpersonate",
        "POST",
        "/admin/impersonate",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "adminStopImpersonating",
        "POST",
        "/admin/stop-impersonating",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "apiKeyCreate",
        "POST",
        "/api-keys",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly name: Schema.optional<Schema.String>;
            readonly prefix: Schema.optional<Schema.String>;
            readonly expiresIn: Schema.optional<Schema.Number>;
            readonly permissions: Schema.optional<
              Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
            >;
            readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
            readonly remaining: Schema.optional<Schema.Number>;
            readonly rateLimit: Schema.optional<
              Schema.Struct<{
                readonly maxRequests: Schema.Number;
                readonly windowMs: Schema.Number;
              }>
            >;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly key: Schema.String;
            readonly apiKey: Schema.Struct<{
              readonly id: Schema.String;
              readonly name: Schema.optional<Schema.String>;
              readonly prefix: Schema.optional<Schema.String>;
              readonly start: Schema.String;
              readonly userId: Schema.String;
              readonly enabled: Schema.Boolean;
              readonly expiresAt: Schema.optional<Schema.Number>;
              readonly lastUsedAt: Schema.optional<Schema.Number>;
              readonly permissions: Schema.optional<
                Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
              >;
              readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
              readonly remaining: Schema.optional<Schema.Number>;
              readonly rateLimit: Schema.optional<
                Schema.Struct<{
                  readonly maxRequests: Schema.Number;
                  readonly windowMs: Schema.Number;
                }>
              >;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
            }>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "apiKeyList",
        "GET",
        "/api-keys",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.$Array<
            Schema.Struct<{
              readonly id: Schema.String;
              readonly name: Schema.optional<Schema.String>;
              readonly prefix: Schema.optional<Schema.String>;
              readonly start: Schema.String;
              readonly userId: Schema.String;
              readonly enabled: Schema.Boolean;
              readonly expiresAt: Schema.optional<Schema.Number>;
              readonly lastUsedAt: Schema.optional<Schema.Number>;
              readonly permissions: Schema.optional<
                Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
              >;
              readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
              readonly remaining: Schema.optional<Schema.Number>;
              readonly rateLimit: Schema.optional<
                Schema.Struct<{
                  readonly maxRequests: Schema.Number;
                  readonly windowMs: Schema.Number;
                }>
              >;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
            }>
          >
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "apiKeyUpdate",
        "PATCH",
        "/api-keys/:keyId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ keyId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly name: Schema.optional<Schema.String>;
            readonly enabled: Schema.optional<Schema.Boolean>;
            readonly expiresAt: Schema.optional<Schema.Number>;
            readonly permissions: Schema.optional<
              Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
            >;
            readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
            readonly remaining: Schema.optional<Schema.Number>;
            readonly rateLimit: Schema.optional<
              Schema.Struct<{
                readonly maxRequests: Schema.Number;
                readonly windowMs: Schema.Number;
              }>
            >;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly name: Schema.optional<Schema.String>;
            readonly prefix: Schema.optional<Schema.String>;
            readonly start: Schema.String;
            readonly userId: Schema.String;
            readonly enabled: Schema.Boolean;
            readonly expiresAt: Schema.optional<Schema.Number>;
            readonly lastUsedAt: Schema.optional<Schema.Number>;
            readonly permissions: Schema.optional<
              Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
            >;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly remaining: Schema.optional<Schema.Number>;
            readonly rateLimit: Schema.optional<
              Schema.Struct<{
                readonly maxRequests: Schema.Number;
                readonly windowMs: Schema.Number;
              }>
            >;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "apiKeyDelete",
        "DELETE",
        "/api-keys/:keyId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ keyId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "ssoRegister",
        "POST",
        "/sso/register",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly issuer: Schema.String;
            readonly domain: Schema.String;
            readonly clientId: Schema.String;
            readonly clientSecret: Schema.String;
            readonly redirectUri: Schema.String;
            readonly discover: Schema.optional<Schema.Boolean>;
            readonly authorizationEndpoint: Schema.optional<Schema.String>;
            readonly tokenEndpoint: Schema.optional<Schema.String>;
            readonly userInfoEndpoint: Schema.optional<Schema.String>;
            readonly jwksEndpoint: Schema.optional<Schema.String>;
            readonly scopes: Schema.optional<Schema.$Array<Schema.String>>;
            readonly usePKCE: Schema.optional<Schema.Boolean>;
            readonly organizationId: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly issuer: Schema.String;
            readonly domain: Schema.String;
            readonly protocol: Schema.Literals<readonly ["oidc"]>;
            readonly clientId: Schema.String;
            readonly redirectUri: Schema.String;
            readonly authorizationEndpoint: Schema.String;
            readonly tokenEndpoint: Schema.String;
            readonly userInfoEndpoint: Schema.optional<Schema.String>;
            readonly jwksEndpoint: Schema.optional<Schema.String>;
            readonly scopes: Schema.$Array<Schema.String>;
            readonly organizationId: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "ssoSignIn",
        "POST",
        "/sign-in/sso",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly email: Schema.optional<Schema.String>;
            readonly domain: Schema.optional<Schema.String>;
            readonly providerId: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly url: Schema.String; readonly state: Schema.String }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "ssoCallback",
        "POST",
        "/sso/callback",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly state: Schema.String; readonly code: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "siweNonce",
        "POST",
        "/siwe/nonce",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly nonce: Schema.String; readonly expiresAt: Schema.Number }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signInSiwe",
        "POST",
        "/sign-in/siwe",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly message: Schema.String; readonly signature: Schema.String }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "signInGoogleOneTap",
        "POST",
        "/sign-in/google-one-tap",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly credential: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly needsEmailVerification: Schema.Boolean;
            readonly secondFactor: Schema.optional<
              Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
            >;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "jwtToken",
        "GET",
        "/token",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "jwtJwks",
        "GET",
        "/jwks",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly keys: Schema.$Array<Schema.$Record<Schema.String, Schema.Unknown>>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcRegisterClient",
        "POST",
        "/oauth2/register",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly name: Schema.String;
            readonly redirectUris: Schema.$Array<Schema.String>;
            readonly type: Schema.optional<Schema.Literals<readonly ["web", "native"]>>;
            readonly skipConsent: Schema.optional<Schema.Boolean>;
            readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly client: Schema.Struct<{
              readonly clientId: Schema.String;
              readonly name: Schema.String;
              readonly redirectUris: Schema.$Array<Schema.String>;
              readonly type: Schema.Literals<readonly ["web", "native"]>;
              readonly skipConsent: Schema.Boolean;
              readonly disabled: Schema.Boolean;
              readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
            }>;
            readonly clientSecret: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcListClients",
        "GET",
        "/oauth2/clients",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.$Array<
            Schema.Struct<{
              readonly clientId: Schema.String;
              readonly name: Schema.String;
              readonly redirectUris: Schema.$Array<Schema.String>;
              readonly type: Schema.Literals<readonly ["web", "native"]>;
              readonly skipConsent: Schema.Boolean;
              readonly disabled: Schema.Boolean;
              readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
            }>
          >
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcUpdateClient",
        "PATCH",
        "/oauth2/clients/:clientId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ clientId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly name: Schema.optional<Schema.String>;
            readonly redirectUris: Schema.optional<Schema.$Array<Schema.String>>;
            readonly skipConsent: Schema.optional<Schema.Boolean>;
            readonly disabled: Schema.optional<Schema.Boolean>;
            readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly clientId: Schema.String;
            readonly name: Schema.String;
            readonly redirectUris: Schema.$Array<Schema.String>;
            readonly type: Schema.Literals<readonly ["web", "native"]>;
            readonly skipConsent: Schema.Boolean;
            readonly disabled: Schema.Boolean;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcDeleteClient",
        "DELETE",
        "/oauth2/clients/:clientId",
        HttpApiEndpoint.StringTree<Schema.Struct<{ clientId: Schema.String }>>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Forbidden,
                { readonly message: string; readonly _tag: "Forbidden" },
                readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Forbidden" }
              >,
              Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcAuthorize",
        "GET",
        "/oauth2/authorize",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<
          Schema.Struct<{
            response_type: Schema.optional<Schema.String>;
            client_id: Schema.optional<Schema.String>;
            redirect_uri: Schema.optional<Schema.String>;
            scope: Schema.optional<Schema.String>;
            state: Schema.optional<Schema.String>;
            code_challenge: Schema.optional<Schema.String>;
            code_challenge_method: Schema.optional<Schema.String>;
            nonce: Schema.optional<Schema.String>;
            prompt: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcConsent",
        "POST",
        "/oauth2/consent",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{ readonly consentCode: Schema.String; readonly accept: Schema.Boolean }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.Struct<{ readonly redirectTo: Schema.String }>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcToken",
        "POST",
        "/oauth2/token",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly grant_type: Schema.String;
            readonly code: Schema.optional<Schema.String>;
            readonly redirect_uri: Schema.optional<Schema.String>;
            readonly code_verifier: Schema.optional<Schema.String>;
            readonly refresh_token: Schema.optional<Schema.String>;
            readonly client_id: Schema.optional<Schema.String>;
            readonly client_secret: Schema.optional<Schema.String>;
            readonly scope: Schema.optional<Schema.String>;
          }>
        >,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly access_token: Schema.String;
            readonly token_type: Schema.String;
            readonly expires_in: Schema.Number;
            readonly refresh_token: Schema.optional<Schema.String>;
            readonly id_token: Schema.optional<Schema.String>;
            readonly scope: Schema.String;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.BadRequest,
                { readonly message: string; readonly _tag: "BadRequest" },
                readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "BadRequest" }
              >,
              Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcUserInfo",
        "GET",
        "/oauth2/userinfo",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.$Record<Schema.String, Schema.Unknown>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.Unauthorized,
                { readonly message: string; readonly _tag: "Unauthorized" },
                readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "Unauthorized" }
              >,
              Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcDiscovery",
        "GET",
        "/.well-known/openid-configuration",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<Schema.$Record<Schema.String, Schema.Unknown>>,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >
    | HttpApiEndpoint.HttpApiEndpoint<
        "oidcJwks",
        "GET",
        "/.well-known/jwks.json",
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.StringTree<never>,
        HttpApiEndpoint.Json<
          Schema.Struct<{
            readonly keys: Schema.$Array<Schema.$Record<Schema.String, Schema.Unknown>>;
          }>
        >,
        HttpApiEndpoint.Json<
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.InternalServerError,
                { readonly message: string; readonly _tag: "InternalServerError" },
                readonly [
                  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
                ],
                { readonly message: string; readonly _tag: "InternalServerError" }
              >,
              Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              never,
              never
            >
          | Schema.decodeTo<
              Schema.declareConstructor<
                S.NotFound,
                { readonly message: string; readonly _tag: "NotFound" },
                readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
                { readonly message: string; readonly _tag: "NotFound" }
              >,
              Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
              never,
              never
            >
        >,
        never,
        never
      >,
    false
  >
>;
```

## authGroup

Email/password + session endpoints.

**Signature**

```ts
export declare const authGroup: HttpApiGroup.HttpApiGroup<
  "auth",
  | HttpApiEndpoint.HttpApiEndpoint<
      "signUp",
      "POST",
      "/sign-up",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly email: Schema.String;
          readonly password: Schema.String;
          readonly name: Schema.optional<Schema.String>;
          readonly attributes: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
          readonly captchaToken: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Conflict,
              { readonly message: string; readonly _tag: "Conflict" },
              readonly [Schema.TaggedStruct<"Conflict", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Conflict" }
            >,
            Schema.TaggedStruct<"Conflict", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signIn",
      "POST",
      "/sign-in",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly email: Schema.String;
          readonly password: Schema.String;
          readonly captchaToken: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signOut",
      "POST",
      "/sign-out",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<never>,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "getSession",
      "GET",
      "/session",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly session: Schema.Struct<{
            readonly id: Schema.String;
            readonly userId: Schema.String;
            readonly expiresAt: Schema.Number;
            readonly createdAt: Schema.Number;
            readonly lastActivityAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
        }>
      >,
      HttpApiEndpoint.Json<
        Schema.decodeTo<
          Schema.declareConstructor<
            S.Unauthorized,
            { readonly message: string; readonly _tag: "Unauthorized" },
            readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
            { readonly message: string; readonly _tag: "Unauthorized" }
          >,
          Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
          never,
          never
        >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "sendVerificationEmail",
      "POST",
      "/email-verification/send",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly email: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "verifyEmail",
      "POST",
      "/email-verification/verify",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "requestPasswordReset",
      "POST",
      "/password-reset/request",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly email: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "resetPassword",
      "POST",
      "/password-reset/reset",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly token: Schema.String; readonly newPassword: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "changePassword",
      "POST",
      "/change-password",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly currentPassword: Schema.String;
          readonly newPassword: Schema.String;
          readonly revokeOtherSessions: Schema.optional<Schema.Boolean>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "updateUser",
      "PATCH",
      "/user",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly name: Schema.optional<Schema.String>;
          readonly image: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly email: Schema.String;
          readonly emailVerified: Schema.Boolean;
          readonly name: Schema.optional<Schema.String>;
          readonly image: Schema.optional<Schema.String>;
          readonly createdAt: Schema.Number;
          readonly updatedAt: Schema.Number;
          readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "listSessions",
      "GET",
      "/sessions",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.$Array<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly userId: Schema.String;
            readonly expiresAt: Schema.Number;
            readonly createdAt: Schema.Number;
            readonly lastActivityAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>
        >
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "revokeSession",
      "DELETE",
      "/sessions/:sessionId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ sessionId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "revokeOtherSessions",
      "POST",
      "/sessions/revoke-others",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "magicLinkSend",
      "POST",
      "/magic-link/send",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly email: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "magicLinkVerify",
      "POST",
      "/magic-link/verify",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "changeEmailRequest",
      "POST",
      "/change-email/request",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly newEmail: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "changeEmailConfirm",
      "POST",
      "/change-email/confirm",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "deleteUserRequest",
      "POST",
      "/delete-user/request",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "deleteUserConfirm",
      "POST",
      "/delete-user/confirm",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly token: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "emailOtpSend",
      "POST",
      "/email-otp/send",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly email: Schema.String;
          readonly purpose: Schema.Literals<
            readonly ["sign-in", "email-verification", "forget-password"]
          >;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signInEmailOtp",
      "POST",
      "/sign-in/email-otp",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly email: Schema.String; readonly otp: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signInAnonymous",
      "POST",
      "/sign-in/anonymous",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signInUsername",
      "POST",
      "/sign-in/username",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly username: Schema.String; readonly password: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "multiSessionList",
      "GET",
      "/multi-session/list",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.$Array<
          Schema.Struct<{
            readonly session: Schema.Struct<{
              readonly id: Schema.String;
              readonly userId: Schema.String;
              readonly expiresAt: Schema.Number;
              readonly createdAt: Schema.Number;
              readonly lastActivityAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
            readonly user: Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>;
          }>
        >
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "multiSessionSetActive",
      "POST",
      "/multi-session/set-active",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly sessionId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "multiSessionRevoke",
      "POST",
      "/multi-session/revoke",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly sessionId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "deviceCode",
      "POST",
      "/device/code",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly clientId: Schema.optional<Schema.String>;
          readonly scopes: Schema.optional<Schema.$Array<Schema.String>>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly deviceCode: Schema.String;
          readonly userCode: Schema.String;
          readonly verificationUri: Schema.String;
          readonly expiresIn: Schema.Number;
          readonly interval: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "deviceToken",
      "POST",
      "/device/token",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly deviceCode: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "deviceApprove",
      "POST",
      "/device/approve",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly userCode: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "deviceDeny",
      "POST",
      "/device/deny",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly userCode: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "phoneOtpSend",
      "POST",
      "/phone-otp/send",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly phoneNumber: Schema.String;
          readonly purpose: Schema.Literals<readonly ["sign-in", "phone-verification"]>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signInPhoneOtp",
      "POST",
      "/sign-in/phone-otp",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly phoneNumber: Schema.String; readonly otp: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "twoFactorEnable",
      "POST",
      "/two-factor/enable",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly password: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly secret: Schema.String;
          readonly totpUri: Schema.String;
          readonly backupCodes: Schema.$Array<Schema.String>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "twoFactorConfirm",
      "POST",
      "/two-factor/confirm",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly code: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "twoFactorDisable",
      "POST",
      "/two-factor/disable",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly password: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "twoFactorRegenerateBackupCodes",
      "POST",
      "/two-factor/regenerate-backup-codes",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly password: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly backupCodes: Schema.$Array<Schema.String> }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "twoFactorVerifyTotp",
      "POST",
      "/two-factor/verify-totp",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly token: Schema.String; readonly code: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "twoFactorVerifyBackupCode",
      "POST",
      "/two-factor/verify-backup-code",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly token: Schema.String; readonly code: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgCreate",
      "POST",
      "/organization/create",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly name: Schema.String;
          readonly slug: Schema.String;
          readonly logo: Schema.optional<Schema.String>;
          readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly name: Schema.String;
          readonly slug: Schema.String;
          readonly logo: Schema.optional<Schema.String>;
          readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgList",
      "GET",
      "/organizations",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.$Array<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly name: Schema.String;
            readonly slug: Schema.String;
            readonly logo: Schema.optional<Schema.String>;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly createdAt: Schema.Number;
          }>
        >
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgGet",
      "GET",
      "/organization/:organizationId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly organization: Schema.Struct<{
            readonly id: Schema.String;
            readonly name: Schema.String;
            readonly slug: Schema.String;
            readonly logo: Schema.optional<Schema.String>;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly createdAt: Schema.Number;
          }>;
          readonly members: Schema.$Array<
            Schema.Struct<{
              readonly id: Schema.String;
              readonly organizationId: Schema.String;
              readonly userId: Schema.String;
              readonly role: Schema.String;
              readonly createdAt: Schema.Number;
            }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgUpdate",
      "PATCH",
      "/organization/:organizationId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly name: Schema.optional<Schema.String>;
          readonly slug: Schema.optional<Schema.String>;
          readonly logo: Schema.optional<Schema.String>;
          readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly name: Schema.String;
          readonly slug: Schema.String;
          readonly logo: Schema.optional<Schema.String>;
          readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgDelete",
      "DELETE",
      "/organization/:organizationId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgSetActive",
      "POST",
      "/organization/set-active",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly organizationId: Schema.NullOr<Schema.String> }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgInvite",
      "POST",
      "/organization/:organizationId/invitations",
      HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly email: Schema.String; readonly role: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly organizationId: Schema.String;
          readonly email: Schema.String;
          readonly role: Schema.String;
          readonly status: Schema.Literals<
            readonly ["pending", "accepted", "rejected", "canceled"]
          >;
          readonly inviterId: Schema.String;
          readonly expiresAt: Schema.Number;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgListInvitations",
      "GET",
      "/organization/:organizationId/invitations",
      HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.$Array<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly organizationId: Schema.String;
            readonly email: Schema.String;
            readonly role: Schema.String;
            readonly status: Schema.Literals<
              readonly ["pending", "accepted", "rejected", "canceled"]
            >;
            readonly inviterId: Schema.String;
            readonly expiresAt: Schema.Number;
            readonly createdAt: Schema.Number;
          }>
        >
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgAcceptInvitation",
      "POST",
      "/invitations/:invitationId/accept",
      HttpApiEndpoint.StringTree<Schema.Struct<{ invitationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly organizationId: Schema.String;
          readonly userId: Schema.String;
          readonly role: Schema.String;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgRejectInvitation",
      "POST",
      "/invitations/:invitationId/reject",
      HttpApiEndpoint.StringTree<Schema.Struct<{ invitationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly organizationId: Schema.String;
          readonly email: Schema.String;
          readonly role: Schema.String;
          readonly status: Schema.Literals<
            readonly ["pending", "accepted", "rejected", "canceled"]
          >;
          readonly inviterId: Schema.String;
          readonly expiresAt: Schema.Number;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgCancelInvitation",
      "POST",
      "/invitations/:invitationId/cancel",
      HttpApiEndpoint.StringTree<Schema.Struct<{ invitationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly organizationId: Schema.String;
          readonly email: Schema.String;
          readonly role: Schema.String;
          readonly status: Schema.Literals<
            readonly ["pending", "accepted", "rejected", "canceled"]
          >;
          readonly inviterId: Schema.String;
          readonly expiresAt: Schema.Number;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgAddMember",
      "POST",
      "/organization/:organizationId/members",
      HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly userId: Schema.String; readonly role: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly organizationId: Schema.String;
          readonly userId: Schema.String;
          readonly role: Schema.String;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgUpdateMemberRole",
      "PATCH",
      "/organization/:organizationId/members",
      HttpApiEndpoint.StringTree<Schema.Struct<{ organizationId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly userId: Schema.String; readonly role: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly organizationId: Schema.String;
          readonly userId: Schema.String;
          readonly role: Schema.String;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "orgRemoveMember",
      "DELETE",
      "/organization/:organizationId/members/:userId",
      HttpApiEndpoint.StringTree<
        Schema.Struct<{ organizationId: Schema.String; userId: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminListUsers",
      "POST",
      "/admin/users/list",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly limit: Schema.optional<Schema.Number>;
          readonly offset: Schema.optional<Schema.Number>;
          readonly searchEmail: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly users: Schema.$Array<
            Schema.Struct<{
              readonly id: Schema.String;
              readonly email: Schema.String;
              readonly emailVerified: Schema.Boolean;
              readonly name: Schema.optional<Schema.String>;
              readonly image: Schema.optional<Schema.String>;
              readonly createdAt: Schema.Number;
              readonly updatedAt: Schema.Number;
              readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
            }>
          >;
          readonly total: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminSetRole",
      "POST",
      "/admin/users/set-role",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly userId: Schema.String; readonly role: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly email: Schema.String;
          readonly emailVerified: Schema.Boolean;
          readonly name: Schema.optional<Schema.String>;
          readonly image: Schema.optional<Schema.String>;
          readonly createdAt: Schema.Number;
          readonly updatedAt: Schema.Number;
          readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminBanUser",
      "POST",
      "/admin/users/ban",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly userId: Schema.String;
          readonly reason: Schema.optional<Schema.String>;
          readonly expiresIn: Schema.optional<Schema.Number>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly email: Schema.String;
          readonly emailVerified: Schema.Boolean;
          readonly name: Schema.optional<Schema.String>;
          readonly image: Schema.optional<Schema.String>;
          readonly createdAt: Schema.Number;
          readonly updatedAt: Schema.Number;
          readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminUnbanUser",
      "POST",
      "/admin/users/unban",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly email: Schema.String;
          readonly emailVerified: Schema.Boolean;
          readonly name: Schema.optional<Schema.String>;
          readonly image: Schema.optional<Schema.String>;
          readonly createdAt: Schema.Number;
          readonly updatedAt: Schema.Number;
          readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminRemoveUser",
      "POST",
      "/admin/users/remove",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminRevokeSessions",
      "POST",
      "/admin/users/revoke-sessions",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminImpersonate",
      "POST",
      "/admin/impersonate",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly userId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "adminStopImpersonating",
      "POST",
      "/admin/stop-impersonating",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly status: Schema.Boolean }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "apiKeyCreate",
      "POST",
      "/api-keys",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly name: Schema.optional<Schema.String>;
          readonly prefix: Schema.optional<Schema.String>;
          readonly expiresIn: Schema.optional<Schema.Number>;
          readonly permissions: Schema.optional<
            Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
          >;
          readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
          readonly remaining: Schema.optional<Schema.Number>;
          readonly rateLimit: Schema.optional<
            Schema.Struct<{ readonly maxRequests: Schema.Number; readonly windowMs: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly key: Schema.String;
          readonly apiKey: Schema.Struct<{
            readonly id: Schema.String;
            readonly name: Schema.optional<Schema.String>;
            readonly prefix: Schema.optional<Schema.String>;
            readonly start: Schema.String;
            readonly userId: Schema.String;
            readonly enabled: Schema.Boolean;
            readonly expiresAt: Schema.optional<Schema.Number>;
            readonly lastUsedAt: Schema.optional<Schema.Number>;
            readonly permissions: Schema.optional<
              Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
            >;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly remaining: Schema.optional<Schema.Number>;
            readonly rateLimit: Schema.optional<
              Schema.Struct<{
                readonly maxRequests: Schema.Number;
                readonly windowMs: Schema.Number;
              }>
            >;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
          }>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "apiKeyList",
      "GET",
      "/api-keys",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.$Array<
          Schema.Struct<{
            readonly id: Schema.String;
            readonly name: Schema.optional<Schema.String>;
            readonly prefix: Schema.optional<Schema.String>;
            readonly start: Schema.String;
            readonly userId: Schema.String;
            readonly enabled: Schema.Boolean;
            readonly expiresAt: Schema.optional<Schema.Number>;
            readonly lastUsedAt: Schema.optional<Schema.Number>;
            readonly permissions: Schema.optional<
              Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
            >;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly remaining: Schema.optional<Schema.Number>;
            readonly rateLimit: Schema.optional<
              Schema.Struct<{
                readonly maxRequests: Schema.Number;
                readonly windowMs: Schema.Number;
              }>
            >;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
          }>
        >
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "apiKeyUpdate",
      "PATCH",
      "/api-keys/:keyId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ keyId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly name: Schema.optional<Schema.String>;
          readonly enabled: Schema.optional<Schema.Boolean>;
          readonly expiresAt: Schema.optional<Schema.Number>;
          readonly permissions: Schema.optional<
            Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
          >;
          readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
          readonly remaining: Schema.optional<Schema.Number>;
          readonly rateLimit: Schema.optional<
            Schema.Struct<{ readonly maxRequests: Schema.Number; readonly windowMs: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly name: Schema.optional<Schema.String>;
          readonly prefix: Schema.optional<Schema.String>;
          readonly start: Schema.String;
          readonly userId: Schema.String;
          readonly enabled: Schema.Boolean;
          readonly expiresAt: Schema.optional<Schema.Number>;
          readonly lastUsedAt: Schema.optional<Schema.Number>;
          readonly permissions: Schema.optional<
            Schema.$Record<Schema.String, Schema.$Array<Schema.String>>
          >;
          readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
          readonly remaining: Schema.optional<Schema.Number>;
          readonly rateLimit: Schema.optional<
            Schema.Struct<{ readonly maxRequests: Schema.Number; readonly windowMs: Schema.Number }>
          >;
          readonly createdAt: Schema.Number;
          readonly updatedAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "apiKeyDelete",
      "DELETE",
      "/api-keys/:keyId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ keyId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "ssoRegister",
      "POST",
      "/sso/register",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly issuer: Schema.String;
          readonly domain: Schema.String;
          readonly clientId: Schema.String;
          readonly clientSecret: Schema.String;
          readonly redirectUri: Schema.String;
          readonly discover: Schema.optional<Schema.Boolean>;
          readonly authorizationEndpoint: Schema.optional<Schema.String>;
          readonly tokenEndpoint: Schema.optional<Schema.String>;
          readonly userInfoEndpoint: Schema.optional<Schema.String>;
          readonly jwksEndpoint: Schema.optional<Schema.String>;
          readonly scopes: Schema.optional<Schema.$Array<Schema.String>>;
          readonly usePKCE: Schema.optional<Schema.Boolean>;
          readonly organizationId: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly id: Schema.String;
          readonly issuer: Schema.String;
          readonly domain: Schema.String;
          readonly protocol: Schema.Literals<readonly ["oidc"]>;
          readonly clientId: Schema.String;
          readonly redirectUri: Schema.String;
          readonly authorizationEndpoint: Schema.String;
          readonly tokenEndpoint: Schema.String;
          readonly userInfoEndpoint: Schema.optional<Schema.String>;
          readonly jwksEndpoint: Schema.optional<Schema.String>;
          readonly scopes: Schema.$Array<Schema.String>;
          readonly organizationId: Schema.optional<Schema.String>;
          readonly createdAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "ssoSignIn",
      "POST",
      "/sign-in/sso",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly email: Schema.optional<Schema.String>;
          readonly domain: Schema.optional<Schema.String>;
          readonly providerId: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly url: Schema.String; readonly state: Schema.String }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "ssoCallback",
      "POST",
      "/sso/callback",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly state: Schema.String; readonly code: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "siweNonce",
      "POST",
      "/siwe/nonce",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly nonce: Schema.String; readonly expiresAt: Schema.Number }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signInSiwe",
      "POST",
      "/sign-in/siwe",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly message: Schema.String; readonly signature: Schema.String }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "signInGoogleOneTap",
      "POST",
      "/sign-in/google-one-tap",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly credential: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly user: Schema.Struct<{
            readonly id: Schema.String;
            readonly email: Schema.String;
            readonly emailVerified: Schema.Boolean;
            readonly name: Schema.optional<Schema.String>;
            readonly image: Schema.optional<Schema.String>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
            readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
          }>;
          readonly needsEmailVerification: Schema.Boolean;
          readonly secondFactor: Schema.optional<
            Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
          >;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "jwtToken",
      "GET",
      "/token",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly token: Schema.String; readonly expiresAt: Schema.Number }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "jwtJwks",
      "GET",
      "/jwks",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly keys: Schema.$Array<Schema.$Record<Schema.String, Schema.Unknown>>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcRegisterClient",
      "POST",
      "/oauth2/register",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly name: Schema.String;
          readonly redirectUris: Schema.$Array<Schema.String>;
          readonly type: Schema.optional<Schema.Literals<readonly ["web", "native"]>>;
          readonly skipConsent: Schema.optional<Schema.Boolean>;
          readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly client: Schema.Struct<{
            readonly clientId: Schema.String;
            readonly name: Schema.String;
            readonly redirectUris: Schema.$Array<Schema.String>;
            readonly type: Schema.Literals<readonly ["web", "native"]>;
            readonly skipConsent: Schema.Boolean;
            readonly disabled: Schema.Boolean;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
          }>;
          readonly clientSecret: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcListClients",
      "GET",
      "/oauth2/clients",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.$Array<
          Schema.Struct<{
            readonly clientId: Schema.String;
            readonly name: Schema.String;
            readonly redirectUris: Schema.$Array<Schema.String>;
            readonly type: Schema.Literals<readonly ["web", "native"]>;
            readonly skipConsent: Schema.Boolean;
            readonly disabled: Schema.Boolean;
            readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
            readonly createdAt: Schema.Number;
            readonly updatedAt: Schema.Number;
          }>
        >
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcUpdateClient",
      "PATCH",
      "/oauth2/clients/:clientId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ clientId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly name: Schema.optional<Schema.String>;
          readonly redirectUris: Schema.optional<Schema.$Array<Schema.String>>;
          readonly skipConsent: Schema.optional<Schema.Boolean>;
          readonly disabled: Schema.optional<Schema.Boolean>;
          readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly clientId: Schema.String;
          readonly name: Schema.String;
          readonly redirectUris: Schema.$Array<Schema.String>;
          readonly type: Schema.Literals<readonly ["web", "native"]>;
          readonly skipConsent: Schema.Boolean;
          readonly disabled: Schema.Boolean;
          readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
          readonly createdAt: Schema.Number;
          readonly updatedAt: Schema.Number;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcDeleteClient",
      "DELETE",
      "/oauth2/clients/:clientId",
      HttpApiEndpoint.StringTree<Schema.Struct<{ clientId: Schema.String }>>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Forbidden,
              { readonly message: string; readonly _tag: "Forbidden" },
              readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Forbidden" }
            >,
            Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcAuthorize",
      "GET",
      "/oauth2/authorize",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<
        Schema.Struct<{
          response_type: Schema.optional<Schema.String>;
          client_id: Schema.optional<Schema.String>;
          redirect_uri: Schema.optional<Schema.String>;
          scope: Schema.optional<Schema.String>;
          state: Schema.optional<Schema.String>;
          code_challenge: Schema.optional<Schema.String>;
          code_challenge_method: Schema.optional<Schema.String>;
          nonce: Schema.optional<Schema.String>;
          prompt: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<HttpApiSchema.NoContent>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcConsent",
      "POST",
      "/oauth2/consent",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{ readonly consentCode: Schema.String; readonly accept: Schema.Boolean }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.Struct<{ readonly redirectTo: Schema.String }>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcToken",
      "POST",
      "/oauth2/token",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly grant_type: Schema.String;
          readonly code: Schema.optional<Schema.String>;
          readonly redirect_uri: Schema.optional<Schema.String>;
          readonly code_verifier: Schema.optional<Schema.String>;
          readonly refresh_token: Schema.optional<Schema.String>;
          readonly client_id: Schema.optional<Schema.String>;
          readonly client_secret: Schema.optional<Schema.String>;
          readonly scope: Schema.optional<Schema.String>;
        }>
      >,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly access_token: Schema.String;
          readonly token_type: Schema.String;
          readonly expires_in: Schema.Number;
          readonly refresh_token: Schema.optional<Schema.String>;
          readonly id_token: Schema.optional<Schema.String>;
          readonly scope: Schema.String;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.BadRequest,
              { readonly message: string; readonly _tag: "BadRequest" },
              readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "BadRequest" }
            >,
            Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcUserInfo",
      "GET",
      "/oauth2/userinfo",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.$Record<Schema.String, Schema.Unknown>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.Unauthorized,
              { readonly message: string; readonly _tag: "Unauthorized" },
              readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "Unauthorized" }
            >,
            Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcDiscovery",
      "GET",
      "/.well-known/openid-configuration",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<Schema.$Record<Schema.String, Schema.Unknown>>,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >
  | HttpApiEndpoint.HttpApiEndpoint<
      "oidcJwks",
      "GET",
      "/.well-known/jwks.json",
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.StringTree<never>,
      HttpApiEndpoint.Json<
        Schema.Struct<{
          readonly keys: Schema.$Array<Schema.$Record<Schema.String, Schema.Unknown>>;
        }>
      >,
      HttpApiEndpoint.Json<
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.InternalServerError,
              { readonly message: string; readonly _tag: "InternalServerError" },
              readonly [
                Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
              ],
              { readonly message: string; readonly _tag: "InternalServerError" }
            >,
            Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
            never,
            never
          >
        | Schema.decodeTo<
            Schema.declareConstructor<
              S.NotFound,
              { readonly message: string; readonly _tag: "NotFound" },
              readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
              { readonly message: string; readonly _tag: "NotFound" }
            >,
            Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
            never,
            never
          >
      >,
      never,
      never
    >,
  false
>;
```

## getOpenApiSpec

Derive the OpenAPI 3.1 document for the auth API from the {@link AuthApi}
contract. The document describes every endpoint path together with its
request/response and error schemas (each carrying its HTTP status code).

Served at `GET {prefix}/openapi.json` when `makeAuthWebHandler` is created
with `{ docs: true }`, and consumable by any OpenAPI tooling.

**Signature**

```ts
export declare const getOpenApiSpec: () => OpenApi.OpenAPISpec;
```
