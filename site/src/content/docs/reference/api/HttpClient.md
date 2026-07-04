---
title: "HttpClient"
description: "API reference for the HttpClient module."
---

## HttpClient overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [makeAuthClient](#makeauthclient)

---

# utils

## makeAuthClient

Derive a typed, Effect-native client for the auth API.

Returns an `Effect` that yields the client; it requires an
`HttpClient.HttpClient` in context (e.g. provide `FetchHttpClient.layer`).
Client methods return `Effect`s over the same `Schema` types and tagged-error
channel as the server contract.

**Signature**

```ts
export declare const makeAuthClient: (baseUrl: string | URL) => Effect<
  {
    readonly auth: {
      readonly signUp: <Mode>(request: {
        readonly payload: {
          readonly email: string;
          readonly password: string;
          readonly name?: string | undefined;
          readonly attributes?: { readonly [x: string]: unknown } | undefined;
          readonly captchaToken?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (Conflict | BadRequest | InternalServerError | TooManyRequests) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signIn: <Mode>(request: {
        readonly payload: {
          readonly email: string;
          readonly password: string;
          readonly captchaToken?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | TooManyRequests | Unauthorized | Forbidden) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signOut: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"] ? never : never | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly getSession: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly session: {
              readonly id: string;
              readonly createdAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly userId: string;
              readonly expiresAt: number;
              readonly lastActivityAt: number;
            };
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"] ? never : Unauthorized | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly sendVerificationEmail: <Mode>(request: {
        readonly payload: { readonly email: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly verifyEmail: <Mode>(request: {
        readonly payload: { readonly token: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly passwordResetRequest: <Mode>(request: {
        readonly payload: { readonly email: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly passwordResetConfirm: <Mode>(request: {
        readonly payload: { readonly token: string; readonly newPassword: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly changePassword: <Mode>(request: {
        readonly payload: {
          readonly newPassword: string;
          readonly currentPassword: string;
          readonly revokeOtherSessions?: boolean | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly updateUser: <Mode>(request: {
        readonly payload: {
          readonly name?: string | undefined;
          readonly image?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly email: string;
            readonly emailVerified: boolean;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly attributes: { readonly [x: string]: unknown };
            readonly name?: string | undefined;
            readonly image?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly listSessions: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          readonly {
            readonly id: string;
            readonly createdAt: number;
            readonly attributes: { readonly [x: string]: unknown };
            readonly userId: string;
            readonly expiresAt: number;
            readonly lastActivityAt: number;
          }[],
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly revokeSession: <Mode>(request: {
        readonly params: { readonly sessionId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly revokeOtherSessions: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly magicLinkSend: <Mode>(request: {
        readonly payload: { readonly email: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly magicLinkVerify: <Mode>(request: {
        readonly payload: { readonly token: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly changeEmailRequest: <Mode>(request: {
        readonly payload: { readonly newEmail: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly changeEmailConfirm: <Mode>(request: {
        readonly payload: { readonly token: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly deleteUserRequest: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly deleteUserConfirm: <Mode>(request: {
        readonly payload: { readonly token: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly emailOtpSend: <Mode>(request: {
        readonly payload: {
          readonly email: string;
          readonly purpose: "sign-in" | "email-verification" | "forget-password";
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signInEmailOtp: <Mode>(request: {
        readonly payload: { readonly email: string; readonly otp: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signInAnonymous: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | TooManyRequests | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signInUsername: <Mode>(request: {
        readonly payload: { readonly password: string; readonly username: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | TooManyRequests | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly multiSessionList: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          readonly {
            readonly session: {
              readonly id: string;
              readonly createdAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly userId: string;
              readonly expiresAt: number;
              readonly lastActivityAt: number;
            };
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
          }[],
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly multiSessionSetActive: <Mode>(request: {
        readonly payload: { readonly sessionId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly multiSessionRevoke: <Mode>(request: {
        readonly payload: { readonly sessionId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly deviceCode: <Mode>(request: {
        readonly payload: {
          readonly clientId?: string | undefined;
          readonly scopes?: readonly string[] | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly deviceCode: string;
            readonly userCode: string;
            readonly verificationUri: string;
            readonly expiresIn: number;
            readonly interval: number;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly deviceToken: <Mode>(request: {
        readonly payload: { readonly deviceCode: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly deviceApprove: <Mode>(request: {
        readonly payload: { readonly userCode: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly deviceDeny: <Mode>(request: {
        readonly payload: { readonly userCode: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly phoneOtpSend: <Mode>(request: {
        readonly payload: {
          readonly purpose: "sign-in" | "phone-verification";
          readonly phoneNumber: string;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signInPhoneOtp: <Mode>(request: {
        readonly payload: { readonly otp: string; readonly phoneNumber: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly twoFactorEnable: <Mode>(request: {
        readonly payload: { readonly password: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly backupCodes: readonly string[];
            readonly secret: string;
            readonly totpUri: string;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly twoFactorConfirm: <Mode>(request: {
        readonly payload: { readonly code: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly twoFactorDisable: <Mode>(request: {
        readonly payload: { readonly password: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly twoFactorRegenerateBackupCodes: <Mode>(request: {
        readonly payload: { readonly password: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly backupCodes: readonly string[] }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly twoFactorVerifyTotp: <Mode>(request: {
        readonly payload: { readonly token: string; readonly code: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | TooManyRequests | Unauthorized | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly twoFactorVerifyBackupCode: <Mode>(request: {
        readonly payload: { readonly token: string; readonly code: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | TooManyRequests | Unauthorized | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgCreate: <Mode>(request: {
        readonly payload: {
          readonly name: string;
          readonly slug: string;
          readonly logo?: string | undefined;
          readonly metadata?: { readonly [x: string]: unknown } | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly name: string;
            readonly id: string;
            readonly createdAt: number;
            readonly metadata: { readonly [x: string]: unknown };
            readonly slug: string;
            readonly logo?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgList: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          readonly {
            readonly name: string;
            readonly id: string;
            readonly createdAt: number;
            readonly metadata: { readonly [x: string]: unknown };
            readonly slug: string;
            readonly logo?: string | undefined;
          }[],
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgGet: <Mode>(request: {
        readonly params: { readonly organizationId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly members: readonly {
              readonly id: string;
              readonly createdAt: number;
              readonly userId: string;
              readonly organizationId: string;
              readonly role: string;
            }[];
            readonly organization: {
              readonly name: string;
              readonly id: string;
              readonly createdAt: number;
              readonly metadata: { readonly [x: string]: unknown };
              readonly slug: string;
              readonly logo?: string | undefined;
            };
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgUpdate: <Mode>(request: {
        readonly params: { readonly organizationId: string };
        readonly payload: {
          readonly name?: string | undefined;
          readonly logo?: string | undefined;
          readonly metadata?: { readonly [x: string]: unknown } | undefined;
          readonly slug?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly name: string;
            readonly id: string;
            readonly createdAt: number;
            readonly metadata: { readonly [x: string]: unknown };
            readonly slug: string;
            readonly logo?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgDelete: <Mode>(request: {
        readonly params: { readonly organizationId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgSetActive: <Mode>(request: {
        readonly payload: { readonly organizationId: string | null };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgInvite: <Mode>(request: {
        readonly params: { readonly organizationId: string };
        readonly payload: { readonly email: string; readonly role: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly email: string;
            readonly createdAt: number;
            readonly expiresAt: number;
            readonly status: "pending" | "accepted" | "rejected" | "canceled";
            readonly organizationId: string;
            readonly role: string;
            readonly inviterId: string;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgListInvitations: <Mode>(request: {
        readonly params: { readonly organizationId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          readonly {
            readonly id: string;
            readonly email: string;
            readonly createdAt: number;
            readonly expiresAt: number;
            readonly status: "pending" | "accepted" | "rejected" | "canceled";
            readonly organizationId: string;
            readonly role: string;
            readonly inviterId: string;
          }[],
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgAcceptInvitation: <Mode>(request: {
        readonly params: { readonly invitationId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly createdAt: number;
            readonly userId: string;
            readonly organizationId: string;
            readonly role: string;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgRejectInvitation: <Mode>(request: {
        readonly params: { readonly invitationId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly email: string;
            readonly createdAt: number;
            readonly expiresAt: number;
            readonly status: "pending" | "accepted" | "rejected" | "canceled";
            readonly organizationId: string;
            readonly role: string;
            readonly inviterId: string;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgCancelInvitation: <Mode>(request: {
        readonly params: { readonly invitationId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly email: string;
            readonly createdAt: number;
            readonly expiresAt: number;
            readonly status: "pending" | "accepted" | "rejected" | "canceled";
            readonly organizationId: string;
            readonly role: string;
            readonly inviterId: string;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgAddMember: <Mode>(request: {
        readonly params: { readonly organizationId: string };
        readonly payload: { readonly userId: string; readonly role: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly createdAt: number;
            readonly userId: string;
            readonly organizationId: string;
            readonly role: string;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgUpdateMemberRole: <Mode>(request: {
        readonly params: { readonly organizationId: string };
        readonly payload: { readonly userId: string; readonly role: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly createdAt: number;
            readonly userId: string;
            readonly organizationId: string;
            readonly role: string;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly orgRemoveMember: <Mode>(request: {
        readonly params: { readonly userId: string; readonly organizationId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminListUsers: <Mode>(request: {
        readonly payload: {
          readonly limit?: number | undefined;
          readonly offset?: number | undefined;
          readonly searchEmail?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly users: readonly {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            }[];
            readonly total: number;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | Forbidden | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminSetRole: <Mode>(request: {
        readonly payload: { readonly userId: string; readonly role: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly email: string;
            readonly emailVerified: boolean;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly attributes: { readonly [x: string]: unknown };
            readonly name?: string | undefined;
            readonly image?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminBanUser: <Mode>(request: {
        readonly payload: {
          readonly userId: string;
          readonly expiresIn?: number | undefined;
          readonly reason?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly email: string;
            readonly emailVerified: boolean;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly attributes: { readonly [x: string]: unknown };
            readonly name?: string | undefined;
            readonly image?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminUnbanUser: <Mode>(request: {
        readonly payload: { readonly userId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly email: string;
            readonly emailVerified: boolean;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly attributes: { readonly [x: string]: unknown };
            readonly name?: string | undefined;
            readonly image?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminRemoveUser: <Mode>(request: {
        readonly payload: { readonly userId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | Forbidden | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminRevokeSessions: <Mode>(request: {
        readonly payload: { readonly userId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | Forbidden | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminImpersonate: <Mode>(request: {
        readonly payload: { readonly userId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (
                    | BadRequest
                    | InternalServerError
                    | TooManyRequests
                    | Unauthorized
                    | Forbidden
                    | NotFound
                  )
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly adminStopImpersonating: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<{ readonly status: boolean }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly apiKeyCreate: <Mode>(request: {
        readonly payload: {
          readonly name?: string | undefined;
          readonly expiresIn?: number | undefined;
          readonly metadata?: { readonly [x: string]: unknown } | undefined;
          readonly prefix?: string | undefined;
          readonly permissions?: { readonly [x: string]: readonly string[] } | undefined;
          readonly remaining?: number | undefined;
          readonly rateLimit?:
            | { readonly maxRequests: number; readonly windowMs: number }
            | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly key: string;
            readonly apiKey: {
              readonly id: string;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly userId: string;
              readonly metadata: { readonly [x: string]: unknown };
              readonly start: string;
              readonly enabled: boolean;
              readonly name?: string | undefined;
              readonly expiresAt?: number | undefined;
              readonly prefix?: string | undefined;
              readonly permissions?: { readonly [x: string]: readonly string[] } | undefined;
              readonly remaining?: number | undefined;
              readonly rateLimit?:
                | { readonly maxRequests: number; readonly windowMs: number }
                | undefined;
              readonly lastUsedAt?: number | undefined;
            };
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly apiKeyList: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          readonly {
            readonly id: string;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly userId: string;
            readonly metadata: { readonly [x: string]: unknown };
            readonly start: string;
            readonly enabled: boolean;
            readonly name?: string | undefined;
            readonly expiresAt?: number | undefined;
            readonly prefix?: string | undefined;
            readonly permissions?: { readonly [x: string]: readonly string[] } | undefined;
            readonly remaining?: number | undefined;
            readonly rateLimit?:
              | { readonly maxRequests: number; readonly windowMs: number }
              | undefined;
            readonly lastUsedAt?: number | undefined;
          }[],
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly apiKeyUpdate: <Mode>(request: {
        readonly params: { readonly keyId: string };
        readonly payload: {
          readonly name?: string | undefined;
          readonly expiresAt?: number | undefined;
          readonly metadata?: { readonly [x: string]: unknown } | undefined;
          readonly permissions?: { readonly [x: string]: readonly string[] } | undefined;
          readonly remaining?: number | undefined;
          readonly rateLimit?:
            | { readonly maxRequests: number; readonly windowMs: number }
            | undefined;
          readonly enabled?: boolean | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly userId: string;
            readonly metadata: { readonly [x: string]: unknown };
            readonly start: string;
            readonly enabled: boolean;
            readonly name?: string | undefined;
            readonly expiresAt?: number | undefined;
            readonly prefix?: string | undefined;
            readonly permissions?: { readonly [x: string]: readonly string[] } | undefined;
            readonly remaining?: number | undefined;
            readonly rateLimit?:
              | { readonly maxRequests: number; readonly windowMs: number }
              | undefined;
            readonly lastUsedAt?: number | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly apiKeyDelete: <Mode>(request: {
        readonly params: { readonly keyId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly ssoRegister: <Mode>(request: {
        readonly payload: {
          readonly clientId: string;
          readonly issuer: string;
          readonly domain: string;
          readonly clientSecret: string;
          readonly redirectUri: string;
          readonly scopes?: readonly string[] | undefined;
          readonly organizationId?: string | undefined;
          readonly discover?: boolean | undefined;
          readonly authorizationEndpoint?: string | undefined;
          readonly tokenEndpoint?: string | undefined;
          readonly userInfoEndpoint?: string | undefined;
          readonly jwksEndpoint?: string | undefined;
          readonly usePKCE?: boolean | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly id: string;
            readonly createdAt: number;
            readonly clientId: string;
            readonly scopes: readonly string[];
            readonly authorizationEndpoint: string;
            readonly tokenEndpoint: string;
            readonly issuer: string;
            readonly domain: string;
            readonly redirectUri: string;
            readonly protocol: "oidc";
            readonly organizationId?: string | undefined;
            readonly userInfoEndpoint?: string | undefined;
            readonly jwksEndpoint?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signInSso: <Mode>(request: {
        readonly payload: {
          readonly email?: string | undefined;
          readonly domain?: string | undefined;
          readonly providerId?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly url: string; readonly state: string }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly ssoCallback: <Mode>(request: {
        readonly payload: { readonly code: string; readonly state: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | TooManyRequests | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly signInGoogleOneTap: <Mode>(request: {
        readonly payload: { readonly credential: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly user: {
              readonly id: string;
              readonly email: string;
              readonly emailVerified: boolean;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly attributes: { readonly [x: string]: unknown };
              readonly name?: string | undefined;
              readonly image?: string | undefined;
            };
            readonly needsEmailVerification: boolean;
            readonly secondFactor?:
              | { readonly expiresAt: number; readonly token: string }
              | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | TooManyRequests | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly jwtToken: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<{ readonly expiresAt: number; readonly token: string }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly jwtJwks: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          { readonly keys: readonly { readonly [x: string]: unknown }[] },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcRegisterClient: <Mode>(request: {
        readonly payload: {
          readonly name: string;
          readonly redirectUris: readonly string[];
          readonly metadata?: { readonly [x: string]: unknown } | undefined;
          readonly type?: "web" | "native" | undefined;
          readonly skipConsent?: boolean | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly client: {
              readonly name: string;
              readonly createdAt: number;
              readonly updatedAt: number;
              readonly clientId: string;
              readonly metadata: { readonly [x: string]: unknown };
              readonly redirectUris: readonly string[];
              readonly type: "web" | "native";
              readonly skipConsent: boolean;
              readonly disabled: boolean;
            };
            readonly clientSecret?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcListClients: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          readonly {
            readonly name: string;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly clientId: string;
            readonly metadata: { readonly [x: string]: unknown };
            readonly redirectUris: readonly string[];
            readonly type: "web" | "native";
            readonly skipConsent: boolean;
            readonly disabled: boolean;
          }[],
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | Forbidden | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcUpdateClient: <Mode>(request: {
        readonly params: { readonly clientId: string };
        readonly payload: {
          readonly name?: string | undefined;
          readonly metadata?: { readonly [x: string]: unknown } | undefined;
          readonly redirectUris?: readonly string[] | undefined;
          readonly skipConsent?: boolean | undefined;
          readonly disabled?: boolean | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly name: string;
            readonly createdAt: number;
            readonly updatedAt: number;
            readonly clientId: string;
            readonly metadata: { readonly [x: string]: unknown };
            readonly redirectUris: readonly string[];
            readonly type: "web" | "native";
            readonly skipConsent: boolean;
            readonly disabled: boolean;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcDeleteClient: <Mode>(request: {
        readonly params: { readonly clientId: string };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            :
                | (BadRequest | InternalServerError | Unauthorized | Forbidden | NotFound)
                | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcAuthorize: <Mode>(request: {
        readonly query: {
          readonly state?: string | undefined;
          readonly response_type?: string | undefined;
          readonly client_id?: string | undefined;
          readonly redirect_uri?: string | undefined;
          readonly scope?: string | undefined;
          readonly code_challenge?: string | undefined;
          readonly code_challenge_method?: string | undefined;
          readonly nonce?: string | undefined;
          readonly prompt?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<void, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcConsent: <Mode>(request: {
        readonly payload: { readonly consentCode: string; readonly accept: boolean };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<{ readonly redirectTo: string }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcToken: <Mode>(request: {
        readonly payload: {
          readonly grant_type: string;
          readonly code?: string | undefined;
          readonly client_id?: string | undefined;
          readonly redirect_uri?: string | undefined;
          readonly scope?: string | undefined;
          readonly code_verifier?: string | undefined;
          readonly refresh_token?: string | undefined;
          readonly client_secret?: string | undefined;
        };
        readonly responseMode?: Mode | undefined;
      }) => Effect<
        HttpApiClient.Client.Response<
          {
            readonly scope: string;
            readonly access_token: string;
            readonly token_type: string;
            readonly expires_in: number;
            readonly refresh_token?: string | undefined;
            readonly id_token?: string | undefined;
          },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (BadRequest | InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcUserInfo: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<{ readonly [x: string]: unknown }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | Unauthorized | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcDiscovery: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<{ readonly [x: string]: unknown }, Mode>,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
      readonly oidcJwks: <Mode>(
        request: void | { readonly responseMode?: Mode | undefined },
      ) => Effect<
        HttpApiClient.Client.Response<
          { readonly keys: readonly { readonly [x: string]: unknown }[] },
          Mode
        >,
        | Error<never>
        | ClientError<never>
        | never
        | HttpClientError
        | ([Mode] extends ["response-only"]
            ? never
            : (InternalServerError | NotFound) | SchemaError),
        | never
        | never
        | never
        | never
        | never
        | ([Mode] extends ["response-only"] ? never : never | never)
      >;
    };
  },
  never,
  HttpClient
>;
```

**Example**

```ts
import { Effect } from "effect";
import { Http } from "effect-auth";

const program = Effect.gen(function* () {
  const client = yield* Http.makeAuthClient("http://localhost:5173");
  const result = yield* client.auth.signIn({
    payload: { email: "user@example.com", password: "password-123" },
  });
  return result.user;
});
```
