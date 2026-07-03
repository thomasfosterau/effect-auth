---
title: "HttpApiSchemas"
description: "API reference for the HttpApiSchemas module."
---

## HttpApiSchemas overview

---

<h2 class="text-delta">Table of contents</h2>

- [utils](#utils)
  - [AddMemberPayload](#addmemberpayload)
  - [AddMemberPayload (type alias)](#addmemberpayload-type-alias)
  - [AdminBanUserPayload](#adminbanuserpayload)
  - [AdminBanUserPayload (type alias)](#adminbanuserpayload-type-alias)
  - [AdminListUsersPayload](#adminlistuserspayload)
  - [AdminListUsersPayload (type alias)](#adminlistuserspayload-type-alias)
  - [AdminSetRolePayload](#adminsetrolepayload)
  - [AdminSetRolePayload (type alias)](#adminsetrolepayload-type-alias)
  - [AdminUserActionPayload](#adminuseractionpayload)
  - [AdminUserActionPayload (type alias)](#adminuseractionpayload-type-alias)
  - [AdminUserListView](#adminuserlistview)
  - [AdminUserListView (type alias)](#adminuserlistview-type-alias)
  - [ApiKeyCreatePayload](#apikeycreatepayload)
  - [ApiKeyCreatePayload (type alias)](#apikeycreatepayload-type-alias)
  - [ApiKeyCreatedView](#apikeycreatedview)
  - [ApiKeyCreatedView (type alias)](#apikeycreatedview-type-alias)
  - [ApiKeyListView](#apikeylistview)
  - [ApiKeyListView (type alias)](#apikeylistview-type-alias)
  - [ApiKeyRateLimit](#apikeyratelimit)
  - [ApiKeyUpdatePayload](#apikeyupdatepayload)
  - [ApiKeyUpdatePayload (type alias)](#apikeyupdatepayload-type-alias)
  - [ApiKeyView](#apikeyview)
  - [ApiKeyView (type alias)](#apikeyview-type-alias)
  - [Attributes](#attributes)
  - [AuthSuccess](#authsuccess)
  - [AuthSuccess (type alias)](#authsuccess-type-alias)
  - [BackupCodesView](#backupcodesview)
  - [BackupCodesView (type alias)](#backupcodesview-type-alias)
  - [BadRequest (class)](#badrequest-class)
  - [BadRequestError](#badrequesterror)
  - [ChangeEmailConfirmPayload](#changeemailconfirmpayload)
  - [ChangeEmailConfirmPayload (type alias)](#changeemailconfirmpayload-type-alias)
  - [ChangeEmailRequestPayload](#changeemailrequestpayload)
  - [ChangeEmailRequestPayload (type alias)](#changeemailrequestpayload-type-alias)
  - [ChangePasswordPayload](#changepasswordpayload)
  - [ChangePasswordPayload (type alias)](#changepasswordpayload-type-alias)
  - [ClaimsView](#claimsview)
  - [ClaimsView (type alias)](#claimsview-type-alias)
  - [Conflict (class)](#conflict-class)
  - [ConflictError](#conflicterror)
  - [CreateOrganizationPayload](#createorganizationpayload)
  - [CreateOrganizationPayload (type alias)](#createorganizationpayload-type-alias)
  - [DeleteUserConfirmPayload](#deleteuserconfirmpayload)
  - [DeleteUserConfirmPayload (type alias)](#deleteuserconfirmpayload-type-alias)
  - [DeviceCodePayload](#devicecodepayload)
  - [DeviceCodePayload (type alias)](#devicecodepayload-type-alias)
  - [DeviceCodeView](#devicecodeview)
  - [DeviceCodeView (type alias)](#devicecodeview-type-alias)
  - [DeviceTokenPayload](#devicetokenpayload)
  - [DeviceTokenPayload (type alias)](#devicetokenpayload-type-alias)
  - [DeviceUserCodePayload](#deviceusercodepayload)
  - [DeviceUserCodePayload (type alias)](#deviceusercodepayload-type-alias)
  - [EmailOtpPurpose](#emailotppurpose)
  - [EmailOtpPurpose (type alias)](#emailotppurpose-type-alias)
  - [EmailOtpSendPayload](#emailotpsendpayload)
  - [EmailOtpSendPayload (type alias)](#emailotpsendpayload-type-alias)
  - [EmailOtpSignInPayload](#emailotpsigninpayload)
  - [EmailOtpSignInPayload (type alias)](#emailotpsigninpayload-type-alias)
  - [Forbidden (class)](#forbidden-class)
  - [ForbiddenError](#forbiddenerror)
  - [FullOrganizationView](#fullorganizationview)
  - [FullOrganizationView (type alias)](#fullorganizationview-type-alias)
  - [GoogleOneTapPayload](#googleonetappayload)
  - [GoogleOneTapPayload (type alias)](#googleonetappayload-type-alias)
  - [InternalError](#internalerror)
  - [InternalServerError (class)](#internalservererror-class)
  - [InvitationListView](#invitationlistview)
  - [InvitationListView (type alias)](#invitationlistview-type-alias)
  - [InvitationView](#invitationview)
  - [InvitationView (type alias)](#invitationview-type-alias)
  - [InviteMemberPayload](#invitememberpayload)
  - [InviteMemberPayload (type alias)](#invitememberpayload-type-alias)
  - [JwksView](#jwksview)
  - [JwksView (type alias)](#jwksview-type-alias)
  - [JwtTokenView](#jwttokenview)
  - [JwtTokenView (type alias)](#jwttokenview-type-alias)
  - [MagicLinkSendPayload](#magiclinksendpayload)
  - [MagicLinkSendPayload (type alias)](#magiclinksendpayload-type-alias)
  - [MagicLinkVerifyPayload](#magiclinkverifypayload)
  - [MagicLinkVerifyPayload (type alias)](#magiclinkverifypayload-type-alias)
  - [MemberView](#memberview)
  - [MemberView (type alias)](#memberview-type-alias)
  - [MultiSessionActionPayload](#multisessionactionpayload)
  - [MultiSessionActionPayload (type alias)](#multisessionactionpayload-type-alias)
  - [MultiSessionListView](#multisessionlistview)
  - [MultiSessionListView (type alias)](#multisessionlistview-type-alias)
  - [NotFound (class)](#notfound-class)
  - [NotFoundError](#notfounderror)
  - [OidcClientCreatedView](#oidcclientcreatedview)
  - [OidcClientCreatedView (type alias)](#oidcclientcreatedview-type-alias)
  - [OidcClientListView](#oidcclientlistview)
  - [OidcClientListView (type alias)](#oidcclientlistview-type-alias)
  - [OidcClientUpdatePayload](#oidcclientupdatepayload)
  - [OidcClientUpdatePayload (type alias)](#oidcclientupdatepayload-type-alias)
  - [OidcClientView](#oidcclientview)
  - [OidcClientView (type alias)](#oidcclientview-type-alias)
  - [OidcConsentPayload](#oidcconsentpayload)
  - [OidcConsentPayload (type alias)](#oidcconsentpayload-type-alias)
  - [OidcRedirectView](#oidcredirectview)
  - [OidcRedirectView (type alias)](#oidcredirectview-type-alias)
  - [OidcRegisterClientPayload](#oidcregisterclientpayload)
  - [OidcRegisterClientPayload (type alias)](#oidcregisterclientpayload-type-alias)
  - [OidcTokenPayload](#oidctokenpayload)
  - [OidcTokenPayload (type alias)](#oidctokenpayload-type-alias)
  - [OidcTokenView](#oidctokenview)
  - [OidcTokenView (type alias)](#oidctokenview-type-alias)
  - [OrganizationListView](#organizationlistview)
  - [OrganizationListView (type alias)](#organizationlistview-type-alias)
  - [OrganizationView](#organizationview)
  - [OrganizationView (type alias)](#organizationview-type-alias)
  - [PhoneOtpPurpose](#phoneotppurpose)
  - [PhoneOtpPurpose (type alias)](#phoneotppurpose-type-alias)
  - [PhoneOtpSendPayload](#phoneotpsendpayload)
  - [PhoneOtpSendPayload (type alias)](#phoneotpsendpayload-type-alias)
  - [PhoneOtpSignInPayload](#phoneotpsigninpayload)
  - [PhoneOtpSignInPayload (type alias)](#phoneotpsigninpayload-type-alias)
  - [RequestPasswordResetPayload](#requestpasswordresetpayload)
  - [RequestPasswordResetPayload (type alias)](#requestpasswordresetpayload-type-alias)
  - [ResetPasswordPayload](#resetpasswordpayload)
  - [ResetPasswordPayload (type alias)](#resetpasswordpayload-type-alias)
  - [SecondFactorChallengeView](#secondfactorchallengeview)
  - [SecondFactorChallengeView (type alias)](#secondfactorchallengeview-type-alias)
  - [SendVerificationEmailPayload](#sendverificationemailpayload)
  - [SendVerificationEmailPayload (type alias)](#sendverificationemailpayload-type-alias)
  - [SessionListView](#sessionlistview)
  - [SessionListView (type alias)](#sessionlistview-type-alias)
  - [SessionView](#sessionview)
  - [SessionView (type alias)](#sessionview-type-alias)
  - [SessionWithUserView](#sessionwithuserview)
  - [SessionWithUserView (type alias)](#sessionwithuserview-type-alias)
  - [SetActiveOrganizationPayload](#setactiveorganizationpayload)
  - [SetActiveOrganizationPayload (type alias)](#setactiveorganizationpayload-type-alias)
  - [SignInPayload](#signinpayload)
  - [SignInPayload (type alias)](#signinpayload-type-alias)
  - [SignUpPayload](#signuppayload)
  - [SignUpPayload (type alias)](#signuppayload-type-alias)
  - [SsoCallbackPayload](#ssocallbackpayload)
  - [SsoCallbackPayload (type alias)](#ssocallbackpayload-type-alias)
  - [SsoProviderView](#ssoproviderview)
  - [SsoProviderView (type alias)](#ssoproviderview-type-alias)
  - [SsoRegisterPayload](#ssoregisterpayload)
  - [SsoRegisterPayload (type alias)](#ssoregisterpayload-type-alias)
  - [SsoSignInPayload](#ssosigninpayload)
  - [SsoSignInPayload (type alias)](#ssosigninpayload-type-alias)
  - [SsoUrlView](#ssourlview)
  - [SsoUrlView (type alias)](#ssourlview-type-alias)
  - [StatusResponse](#statusresponse)
  - [StatusResponse (type alias)](#statusresponse-type-alias)
  - [TwoFactorConfirmPayload](#twofactorconfirmpayload)
  - [TwoFactorConfirmPayload (type alias)](#twofactorconfirmpayload-type-alias)
  - [TwoFactorEnableView](#twofactorenableview)
  - [TwoFactorEnableView (type alias)](#twofactorenableview-type-alias)
  - [TwoFactorPasswordPayload](#twofactorpasswordpayload)
  - [TwoFactorPasswordPayload (type alias)](#twofactorpasswordpayload-type-alias)
  - [TwoFactorVerifyPayload](#twofactorverifypayload)
  - [TwoFactorVerifyPayload (type alias)](#twofactorverifypayload-type-alias)
  - [Unauthorized (class)](#unauthorized-class)
  - [UnauthorizedError](#unauthorizederror)
  - [UpdateMemberRolePayload](#updatememberrolepayload)
  - [UpdateMemberRolePayload (type alias)](#updatememberrolepayload-type-alias)
  - [UpdateOrganizationPayload](#updateorganizationpayload)
  - [UpdateOrganizationPayload (type alias)](#updateorganizationpayload-type-alias)
  - [UpdateUserPayload](#updateuserpayload)
  - [UpdateUserPayload (type alias)](#updateuserpayload-type-alias)
  - [UserView](#userview)
  - [UserView (type alias)](#userview-type-alias)
  - [UsernameSignInPayload](#usernamesigninpayload)
  - [UsernameSignInPayload (type alias)](#usernamesigninpayload-type-alias)
  - [VerifyEmailPayload](#verifyemailpayload)
  - [VerifyEmailPayload (type alias)](#verifyemailpayload-type-alias)
  - [encodeSession](#encodesession)
  - [encodeSessionWithUser](#encodesessionwithuser)
  - [encodeUser](#encodeuser)

---

# utils

## AddMemberPayload

Request body for adding a member directly.

**Signature**

```ts
export declare const AddMemberPayload: Schema.Struct<{
  readonly userId: Schema.String;
  readonly role: Schema.String;
}>;
```

## AddMemberPayload (type alias)

**Signature**

```ts
export type AddMemberPayload = typeof AddMemberPayload.Type;
```

## AdminBanUserPayload

Request body for banning a user (admin).

**Signature**

```ts
export declare const AdminBanUserPayload: Schema.Struct<{
  readonly userId: Schema.String;
  readonly reason: Schema.optional<Schema.String>;
  readonly expiresIn: Schema.optional<Schema.Number>;
}>;
```

## AdminBanUserPayload (type alias)

**Signature**

```ts
export type AdminBanUserPayload = typeof AdminBanUserPayload.Type;
```

## AdminListUsersPayload

Request body for listing users (admin).

**Signature**

```ts
export declare const AdminListUsersPayload: Schema.Struct<{
  readonly limit: Schema.optional<Schema.Number>;
  readonly offset: Schema.optional<Schema.Number>;
  readonly searchEmail: Schema.optional<Schema.String>;
}>;
```

## AdminListUsersPayload (type alias)

**Signature**

```ts
export type AdminListUsersPayload = typeof AdminListUsersPayload.Type;
```

## AdminSetRolePayload

Request body for setting a user's role (admin).

**Signature**

```ts
export declare const AdminSetRolePayload: Schema.Struct<{
  readonly userId: Schema.String;
  readonly role: Schema.String;
}>;
```

## AdminSetRolePayload (type alias)

**Signature**

```ts
export type AdminSetRolePayload = typeof AdminSetRolePayload.Type;
```

## AdminUserActionPayload

Request body identifying a target user (admin).

**Signature**

```ts
export declare const AdminUserActionPayload: Schema.Struct<{ readonly userId: Schema.String }>;
```

## AdminUserActionPayload (type alias)

**Signature**

```ts
export type AdminUserActionPayload = typeof AdminUserActionPayload.Type;
```

## AdminUserListView

Paginated user listing (admin).

**Signature**

```ts
export declare const AdminUserListView: Schema.Struct<{
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
}>;
```

## AdminUserListView (type alias)

**Signature**

```ts
export type AdminUserListView = typeof AdminUserListView.Type;
```

## ApiKeyCreatePayload

Request body for creating an API key.

**Signature**

```ts
export declare const ApiKeyCreatePayload: Schema.Struct<{
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
}>;
```

## ApiKeyCreatePayload (type alias)

**Signature**

```ts
export type ApiKeyCreatePayload = typeof ApiKeyCreatePayload.Type;
```

## ApiKeyCreatedView

Result of creating an API key: the plaintext key (shown once) + its record.

**Signature**

```ts
export declare const ApiKeyCreatedView: Schema.Struct<{
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
      Schema.Struct<{ readonly maxRequests: Schema.Number; readonly windowMs: Schema.Number }>
    >;
    readonly createdAt: Schema.Number;
    readonly updatedAt: Schema.Number;
  }>;
}>;
```

## ApiKeyCreatedView (type alias)

**Signature**

```ts
export type ApiKeyCreatedView = typeof ApiKeyCreatedView.Type;
```

## ApiKeyListView

**Signature**

```ts
export declare const ApiKeyListView: Schema.$Array<
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
>;
```

## ApiKeyListView (type alias)

**Signature**

```ts
export type ApiKeyListView = typeof ApiKeyListView.Type;
```

## ApiKeyRateLimit

Per-key rate-limit configuration.

**Signature**

```ts
export declare const ApiKeyRateLimit: Schema.Struct<{
  readonly maxRequests: Schema.Number;
  readonly windowMs: Schema.Number;
}>;
```

## ApiKeyUpdatePayload

Request body for updating an API key.

**Signature**

```ts
export declare const ApiKeyUpdatePayload: Schema.Struct<{
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
}>;
```

## ApiKeyUpdatePayload (type alias)

**Signature**

```ts
export type ApiKeyUpdatePayload = typeof ApiKeyUpdatePayload.Type;
```

## ApiKeyView

Public view of an API key (never includes the plaintext or hash).

**Signature**

```ts
export declare const ApiKeyView: Schema.Struct<{
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
}>;
```

## ApiKeyView (type alias)

**Signature**

```ts
export type ApiKeyView = typeof ApiKeyView.Type;
```

## Attributes

Arbitrary JSON attributes bag.

**Signature**

```ts
export declare const Attributes: Schema.$Record<Schema.String, Schema.Unknown>;
```

## AuthSuccess

Successful authentication result. The session itself is conveyed via the
session cookie (`Set-Cookie`); `needsEmailVerification` lets a client branch
when verification is still required, and `secondFactor` is present when the
user must redeem a two-factor challenge to obtain a session.

**Signature**

```ts
export declare const AuthSuccess: Schema.Struct<{
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
}>;
```

## AuthSuccess (type alias)

**Signature**

```ts
export type AuthSuccess = typeof AuthSuccess.Type;
```

## BackupCodesView

Freshly regenerated plaintext backup codes (shown once).

**Signature**

```ts
export declare const BackupCodesView: Schema.Struct<{
  readonly backupCodes: Schema.$Array<Schema.String>;
}>;
```

## BackupCodesView (type alias)

**Signature**

```ts
export type BackupCodesView = typeof BackupCodesView.Type;
```

## BadRequest (class)

400 — malformed/invalid request.

**Signature**

```ts
export declare class BadRequest
```

## BadRequestError

**Signature**

```ts
export declare const BadRequestError: Schema.decodeTo<
  Schema.declareConstructor<
    BadRequest,
    { readonly message: string; readonly _tag: "BadRequest" },
    readonly [Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>],
    { readonly message: string; readonly _tag: "BadRequest" }
  >,
  Schema.TaggedStruct<"BadRequest", { readonly message: Schema.String }>,
  never,
  never
>;
```

## ChangeEmailConfirmPayload

Request body for confirming an email change by token.

**Signature**

```ts
export declare const ChangeEmailConfirmPayload: Schema.Struct<{ readonly token: Schema.String }>;
```

## ChangeEmailConfirmPayload (type alias)

**Signature**

```ts
export type ChangeEmailConfirmPayload = typeof ChangeEmailConfirmPayload.Type;
```

## ChangeEmailRequestPayload

Request body for requesting an email change (authenticated).

**Signature**

```ts
export declare const ChangeEmailRequestPayload: Schema.Struct<{ readonly newEmail: Schema.String }>;
```

## ChangeEmailRequestPayload (type alias)

**Signature**

```ts
export type ChangeEmailRequestPayload = typeof ChangeEmailRequestPayload.Type;
```

## ChangePasswordPayload

Request body for changing the authenticated user's password.

**Signature**

```ts
export declare const ChangePasswordPayload: Schema.Struct<{
  readonly currentPassword: Schema.String;
  readonly newPassword: Schema.String;
  readonly revokeOtherSessions: Schema.optional<Schema.Boolean>;
}>;
```

## ChangePasswordPayload (type alias)

**Signature**

```ts
export type ChangePasswordPayload = typeof ChangePasswordPayload.Type;
```

## ClaimsView

UserInfo response / OpenID Provider Metadata: open-ended claim records.

**Signature**

```ts
export declare const ClaimsView: Schema.$Record<Schema.String, Schema.Unknown>;
```

## ClaimsView (type alias)

**Signature**

```ts
export type ClaimsView = typeof ClaimsView.Type;
```

## Conflict (class)

409 — conflict (e.g. user already exists).

**Signature**

```ts
export declare class Conflict
```

## ConflictError

**Signature**

```ts
export declare const ConflictError: Schema.decodeTo<
  Schema.declareConstructor<
    Conflict,
    { readonly message: string; readonly _tag: "Conflict" },
    readonly [Schema.TaggedStruct<"Conflict", { readonly message: Schema.String }>],
    { readonly message: string; readonly _tag: "Conflict" }
  >,
  Schema.TaggedStruct<"Conflict", { readonly message: Schema.String }>,
  never,
  never
>;
```

## CreateOrganizationPayload

Request body for creating an organization.

**Signature**

```ts
export declare const CreateOrganizationPayload: Schema.Struct<{
  readonly name: Schema.String;
  readonly slug: Schema.String;
  readonly logo: Schema.optional<Schema.String>;
  readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
}>;
```

## CreateOrganizationPayload (type alias)

**Signature**

```ts
export type CreateOrganizationPayload = typeof CreateOrganizationPayload.Type;
```

## DeleteUserConfirmPayload

Request body for confirming account deletion by token.

**Signature**

```ts
export declare const DeleteUserConfirmPayload: Schema.Struct<{ readonly token: Schema.String }>;
```

## DeleteUserConfirmPayload (type alias)

**Signature**

```ts
export type DeleteUserConfirmPayload = typeof DeleteUserConfirmPayload.Type;
```

## DeviceCodePayload

Request body for starting a device authorization request.

**Signature**

```ts
export declare const DeviceCodePayload: Schema.Struct<{
  readonly clientId: Schema.optional<Schema.String>;
  readonly scopes: Schema.optional<Schema.$Array<Schema.String>>;
}>;
```

## DeviceCodePayload (type alias)

**Signature**

```ts
export type DeviceCodePayload = typeof DeviceCodePayload.Type;
```

## DeviceCodeView

Response for a started device authorization request.

**Signature**

```ts
export declare const DeviceCodeView: Schema.Struct<{
  readonly deviceCode: Schema.String;
  readonly userCode: Schema.String;
  readonly verificationUri: Schema.String;
  readonly expiresIn: Schema.Number;
  readonly interval: Schema.Number;
}>;
```

## DeviceCodeView (type alias)

**Signature**

```ts
export type DeviceCodeView = typeof DeviceCodeView.Type;
```

## DeviceTokenPayload

Request body for polling the device token endpoint.

**Signature**

```ts
export declare const DeviceTokenPayload: Schema.Struct<{ readonly deviceCode: Schema.String }>;
```

## DeviceTokenPayload (type alias)

**Signature**

```ts
export type DeviceTokenPayload = typeof DeviceTokenPayload.Type;
```

## DeviceUserCodePayload

Request body for approving/denying a device user code.

**Signature**

```ts
export declare const DeviceUserCodePayload: Schema.Struct<{ readonly userCode: Schema.String }>;
```

## DeviceUserCodePayload (type alias)

**Signature**

```ts
export type DeviceUserCodePayload = typeof DeviceUserCodePayload.Type;
```

## EmailOtpPurpose

The purposes an email OTP can be issued for.

**Signature**

```ts
export declare const EmailOtpPurpose: Schema.Literals<
  readonly ["sign-in", "email-verification", "forget-password"]
>;
```

## EmailOtpPurpose (type alias)

**Signature**

```ts
export type EmailOtpPurpose = typeof EmailOtpPurpose.Type;
```

## EmailOtpSendPayload

Request body for sending an email OTP.

**Signature**

```ts
export declare const EmailOtpSendPayload: Schema.Struct<{
  readonly email: Schema.String;
  readonly purpose: Schema.Literals<readonly ["sign-in", "email-verification", "forget-password"]>;
}>;
```

## EmailOtpSendPayload (type alias)

**Signature**

```ts
export type EmailOtpSendPayload = typeof EmailOtpSendPayload.Type;
```

## EmailOtpSignInPayload

Request body for signing in with an email OTP.

**Signature**

```ts
export declare const EmailOtpSignInPayload: Schema.Struct<{
  readonly email: Schema.String;
  readonly otp: Schema.String;
}>;
```

## EmailOtpSignInPayload (type alias)

**Signature**

```ts
export type EmailOtpSignInPayload = typeof EmailOtpSignInPayload.Type;
```

## Forbidden (class)

403 — authenticated but not allowed (e.g. email not verified).

**Signature**

```ts
export declare class Forbidden
```

## ForbiddenError

**Signature**

```ts
export declare const ForbiddenError: Schema.decodeTo<
  Schema.declareConstructor<
    Forbidden,
    { readonly message: string; readonly _tag: "Forbidden" },
    readonly [Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>],
    { readonly message: string; readonly _tag: "Forbidden" }
  >,
  Schema.TaggedStruct<"Forbidden", { readonly message: Schema.String }>,
  never,
  never
>;
```

## FullOrganizationView

An organization together with its members.

**Signature**

```ts
export declare const FullOrganizationView: Schema.Struct<{
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
}>;
```

## FullOrganizationView (type alias)

**Signature**

```ts
export type FullOrganizationView = typeof FullOrganizationView.Type;
```

## GoogleOneTapPayload

Request body for a Google One Tap sign-in.

**Signature**

```ts
export declare const GoogleOneTapPayload: Schema.Struct<{ readonly credential: Schema.String }>;
```

## GoogleOneTapPayload (type alias)

**Signature**

```ts
export type GoogleOneTapPayload = typeof GoogleOneTapPayload.Type;
```

## InternalError

**Signature**

```ts
export declare const InternalError: Schema.decodeTo<
  Schema.declareConstructor<
    InternalServerError,
    { readonly message: string; readonly _tag: "InternalServerError" },
    readonly [Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>],
    { readonly message: string; readonly _tag: "InternalServerError" }
  >,
  Schema.TaggedStruct<"InternalServerError", { readonly message: Schema.String }>,
  never,
  never
>;
```

## InternalServerError (class)

500 — unexpected server error.

**Signature**

```ts
export declare class InternalServerError
```

## InvitationListView

**Signature**

```ts
export declare const InvitationListView: Schema.$Array<
  Schema.Struct<{
    readonly id: Schema.String;
    readonly organizationId: Schema.String;
    readonly email: Schema.String;
    readonly role: Schema.String;
    readonly status: Schema.Literals<readonly ["pending", "accepted", "rejected", "canceled"]>;
    readonly inviterId: Schema.String;
    readonly expiresAt: Schema.Number;
    readonly createdAt: Schema.Number;
  }>
>;
```

## InvitationListView (type alias)

**Signature**

```ts
export type InvitationListView = typeof InvitationListView.Type;
```

## InvitationView

Public view of an invitation.

**Signature**

```ts
export declare const InvitationView: Schema.Struct<{
  readonly id: Schema.String;
  readonly organizationId: Schema.String;
  readonly email: Schema.String;
  readonly role: Schema.String;
  readonly status: Schema.Literals<readonly ["pending", "accepted", "rejected", "canceled"]>;
  readonly inviterId: Schema.String;
  readonly expiresAt: Schema.Number;
  readonly createdAt: Schema.Number;
}>;
```

## InvitationView (type alias)

**Signature**

```ts
export type InvitationView = typeof InvitationView.Type;
```

## InviteMemberPayload

Request body for inviting a member.

**Signature**

```ts
export declare const InviteMemberPayload: Schema.Struct<{
  readonly email: Schema.String;
  readonly role: Schema.String;
}>;
```

## InviteMemberPayload (type alias)

**Signature**

```ts
export type InviteMemberPayload = typeof InviteMemberPayload.Type;
```

## JwksView

A JWKS document (opaque key objects).

**Signature**

```ts
export declare const JwksView: Schema.Struct<{
  readonly keys: Schema.$Array<Schema.$Record<Schema.String, Schema.Unknown>>;
}>;
```

## JwksView (type alias)

**Signature**

```ts
export type JwksView = typeof JwksView.Type;
```

## JwtTokenView

A minted JWT plus its expiry (epoch millis).

**Signature**

```ts
export declare const JwtTokenView: Schema.Struct<{
  readonly token: Schema.String;
  readonly expiresAt: Schema.Number;
}>;
```

## JwtTokenView (type alias)

**Signature**

```ts
export type JwtTokenView = typeof JwtTokenView.Type;
```

## MagicLinkSendPayload

Request body for requesting a magic link email.

**Signature**

```ts
export declare const MagicLinkSendPayload: Schema.Struct<{ readonly email: Schema.String }>;
```

## MagicLinkSendPayload (type alias)

**Signature**

```ts
export type MagicLinkSendPayload = typeof MagicLinkSendPayload.Type;
```

## MagicLinkVerifyPayload

Request body for redeeming a magic link token.

**Signature**

```ts
export declare const MagicLinkVerifyPayload: Schema.Struct<{ readonly token: Schema.String }>;
```

## MagicLinkVerifyPayload (type alias)

**Signature**

```ts
export type MagicLinkVerifyPayload = typeof MagicLinkVerifyPayload.Type;
```

## MemberView

Public view of an organization membership.

**Signature**

```ts
export declare const MemberView: Schema.Struct<{
  readonly id: Schema.String;
  readonly organizationId: Schema.String;
  readonly userId: Schema.String;
  readonly role: Schema.String;
  readonly createdAt: Schema.Number;
}>;
```

## MemberView (type alias)

**Signature**

```ts
export type MemberView = typeof MemberView.Type;
```

## MultiSessionActionPayload

Request body for multi-session set-active / revoke.

**Signature**

```ts
export declare const MultiSessionActionPayload: Schema.Struct<{
  readonly sessionId: Schema.String;
}>;
```

## MultiSessionActionPayload (type alias)

**Signature**

```ts
export type MultiSessionActionPayload = typeof MultiSessionActionPayload.Type;
```

## MultiSessionListView

List of a device's valid sessions (multi-session).

**Signature**

```ts
export declare const MultiSessionListView: Schema.$Array<
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
>;
```

## MultiSessionListView (type alias)

**Signature**

```ts
export type MultiSessionListView = typeof MultiSessionListView.Type;
```

## NotFound (class)

404 — resource or optional feature not available (e.g. plugin not enabled).

**Signature**

```ts
export declare class NotFound
```

## NotFoundError

**Signature**

```ts
export declare const NotFoundError: Schema.decodeTo<
  Schema.declareConstructor<
    NotFound,
    { readonly message: string; readonly _tag: "NotFound" },
    readonly [Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>],
    { readonly message: string; readonly _tag: "NotFound" }
  >,
  Schema.TaggedStruct<"NotFound", { readonly message: Schema.String }>,
  never,
  never
>;
```

## OidcClientCreatedView

Result of registering a client: the plaintext secret is shown exactly once.

**Signature**

```ts
export declare const OidcClientCreatedView: Schema.Struct<{
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
}>;
```

## OidcClientCreatedView (type alias)

**Signature**

```ts
export type OidcClientCreatedView = typeof OidcClientCreatedView.Type;
```

## OidcClientListView

**Signature**

```ts
export declare const OidcClientListView: Schema.$Array<
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
>;
```

## OidcClientListView (type alias)

**Signature**

```ts
export type OidcClientListView = typeof OidcClientListView.Type;
```

## OidcClientUpdatePayload

Request body for updating an OIDC client (admin-gated).

**Signature**

```ts
export declare const OidcClientUpdatePayload: Schema.Struct<{
  readonly name: Schema.optional<Schema.String>;
  readonly redirectUris: Schema.optional<Schema.$Array<Schema.String>>;
  readonly skipConsent: Schema.optional<Schema.Boolean>;
  readonly disabled: Schema.optional<Schema.Boolean>;
  readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
}>;
```

## OidcClientUpdatePayload (type alias)

**Signature**

```ts
export type OidcClientUpdatePayload = typeof OidcClientUpdatePayload.Type;
```

## OidcClientView

Public view of a registered OIDC client (never exposes the secret hash).

**Signature**

```ts
export declare const OidcClientView: Schema.Struct<{
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
```

## OidcClientView (type alias)

**Signature**

```ts
export type OidcClientView = typeof OidcClientView.Type;
```

## OidcConsentPayload

Request body for resolving a pending consent request.

**Signature**

```ts
export declare const OidcConsentPayload: Schema.Struct<{
  readonly consentCode: Schema.String;
  readonly accept: Schema.Boolean;
}>;
```

## OidcConsentPayload (type alias)

**Signature**

```ts
export type OidcConsentPayload = typeof OidcConsentPayload.Type;
```

## OidcRedirectView

Where to send the user after a consent decision.

**Signature**

```ts
export declare const OidcRedirectView: Schema.Struct<{ readonly redirectTo: Schema.String }>;
```

## OidcRedirectView (type alias)

**Signature**

```ts
export type OidcRedirectView = typeof OidcRedirectView.Type;
```

## OidcRegisterClientPayload

Request body for registering an OIDC client (admin-gated).

**Signature**

```ts
export declare const OidcRegisterClientPayload: Schema.Struct<{
  readonly name: Schema.String;
  readonly redirectUris: Schema.$Array<Schema.String>;
  readonly type: Schema.optional<Schema.Literals<readonly ["web", "native"]>>;
  readonly skipConsent: Schema.optional<Schema.Boolean>;
  readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
}>;
```

## OidcRegisterClientPayload (type alias)

**Signature**

```ts
export type OidcRegisterClientPayload = typeof OidcRegisterClientPayload.Type;
```

## OidcTokenPayload

Token endpoint request (RFC 6749 snake_case). Accepted as JSON or
`application/x-www-form-urlencoded`; client credentials may instead come
from a Basic Authorization header.

**Signature**

```ts
export declare const OidcTokenPayload: Schema.Struct<{
  readonly grant_type: Schema.String;
  readonly code: Schema.optional<Schema.String>;
  readonly redirect_uri: Schema.optional<Schema.String>;
  readonly code_verifier: Schema.optional<Schema.String>;
  readonly refresh_token: Schema.optional<Schema.String>;
  readonly client_id: Schema.optional<Schema.String>;
  readonly client_secret: Schema.optional<Schema.String>;
  readonly scope: Schema.optional<Schema.String>;
}>;
```

## OidcTokenPayload (type alias)

**Signature**

```ts
export type OidcTokenPayload = typeof OidcTokenPayload.Type;
```

## OidcTokenView

Token endpoint success response (RFC 6749 snake_case).

**Signature**

```ts
export declare const OidcTokenView: Schema.Struct<{
  readonly access_token: Schema.String;
  readonly token_type: Schema.String;
  readonly expires_in: Schema.Number;
  readonly refresh_token: Schema.optional<Schema.String>;
  readonly id_token: Schema.optional<Schema.String>;
  readonly scope: Schema.String;
}>;
```

## OidcTokenView (type alias)

**Signature**

```ts
export type OidcTokenView = typeof OidcTokenView.Type;
```

## OrganizationListView

**Signature**

```ts
export declare const OrganizationListView: Schema.$Array<
  Schema.Struct<{
    readonly id: Schema.String;
    readonly name: Schema.String;
    readonly slug: Schema.String;
    readonly logo: Schema.optional<Schema.String>;
    readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
    readonly createdAt: Schema.Number;
  }>
>;
```

## OrganizationListView (type alias)

**Signature**

```ts
export type OrganizationListView = typeof OrganizationListView.Type;
```

## OrganizationView

Public view of an organization.

**Signature**

```ts
export declare const OrganizationView: Schema.Struct<{
  readonly id: Schema.String;
  readonly name: Schema.String;
  readonly slug: Schema.String;
  readonly logo: Schema.optional<Schema.String>;
  readonly metadata: Schema.$Record<Schema.String, Schema.Unknown>;
  readonly createdAt: Schema.Number;
}>;
```

## OrganizationView (type alias)

**Signature**

```ts
export type OrganizationView = typeof OrganizationView.Type;
```

## PhoneOtpPurpose

The purposes a phone OTP can be issued for.

**Signature**

```ts
export declare const PhoneOtpPurpose: Schema.Literals<readonly ["sign-in", "phone-verification"]>;
```

## PhoneOtpPurpose (type alias)

**Signature**

```ts
export type PhoneOtpPurpose = typeof PhoneOtpPurpose.Type;
```

## PhoneOtpSendPayload

Request body for sending a phone (SMS) OTP.

**Signature**

```ts
export declare const PhoneOtpSendPayload: Schema.Struct<{
  readonly phoneNumber: Schema.String;
  readonly purpose: Schema.Literals<readonly ["sign-in", "phone-verification"]>;
}>;
```

## PhoneOtpSendPayload (type alias)

**Signature**

```ts
export type PhoneOtpSendPayload = typeof PhoneOtpSendPayload.Type;
```

## PhoneOtpSignInPayload

Request body for signing in with a phone OTP.

**Signature**

```ts
export declare const PhoneOtpSignInPayload: Schema.Struct<{
  readonly phoneNumber: Schema.String;
  readonly otp: Schema.String;
}>;
```

## PhoneOtpSignInPayload (type alias)

**Signature**

```ts
export type PhoneOtpSignInPayload = typeof PhoneOtpSignInPayload.Type;
```

## RequestPasswordResetPayload

Request body for requesting a password reset email.

**Signature**

```ts
export declare const RequestPasswordResetPayload: Schema.Struct<{ readonly email: Schema.String }>;
```

## RequestPasswordResetPayload (type alias)

**Signature**

```ts
export type RequestPasswordResetPayload = typeof RequestPasswordResetPayload.Type;
```

## ResetPasswordPayload

Request body for completing a password reset.

**Signature**

```ts
export declare const ResetPasswordPayload: Schema.Struct<{
  readonly token: Schema.String;
  readonly newPassword: Schema.String;
}>;
```

## ResetPasswordPayload (type alias)

**Signature**

```ts
export type ResetPasswordPayload = typeof ResetPasswordPayload.Type;
```

## SecondFactorChallengeView

A pending second-factor challenge returned instead of a session.

**Signature**

```ts
export declare const SecondFactorChallengeView: Schema.Struct<{
  readonly token: Schema.String;
  readonly expiresAt: Schema.Number;
}>;
```

## SecondFactorChallengeView (type alias)

**Signature**

```ts
export type SecondFactorChallengeView = typeof SecondFactorChallengeView.Type;
```

## SendVerificationEmailPayload

Request body for sending/resending an email verification.

**Signature**

```ts
export declare const SendVerificationEmailPayload: Schema.Struct<{ readonly email: Schema.String }>;
```

## SendVerificationEmailPayload (type alias)

**Signature**

```ts
export type SendVerificationEmailPayload = typeof SendVerificationEmailPayload.Type;
```

## SessionListView

List of the authenticated user's active sessions.

**Signature**

```ts
export declare const SessionListView: Schema.$Array<
  Schema.Struct<{
    readonly id: Schema.String;
    readonly userId: Schema.String;
    readonly expiresAt: Schema.Number;
    readonly createdAt: Schema.Number;
    readonly lastActivityAt: Schema.Number;
    readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
  }>
>;
```

## SessionListView (type alias)

**Signature**

```ts
export type SessionListView = typeof SessionListView.Type;
```

## SessionView

Public view of a session (timestamps as epoch millis).

**Signature**

```ts
export declare const SessionView: Schema.Struct<{
  readonly id: Schema.String;
  readonly userId: Schema.String;
  readonly expiresAt: Schema.Number;
  readonly createdAt: Schema.Number;
  readonly lastActivityAt: Schema.Number;
  readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
}>;
```

## SessionView (type alias)

**Signature**

```ts
export type SessionView = typeof SessionView.Type;
```

## SessionWithUserView

A session together with its user.

**Signature**

```ts
export declare const SessionWithUserView: Schema.Struct<{
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
}>;
```

## SessionWithUserView (type alias)

**Signature**

```ts
export type SessionWithUserView = typeof SessionWithUserView.Type;
```

## SetActiveOrganizationPayload

Request body for setting the session's active organization (null clears it).

**Signature**

```ts
export declare const SetActiveOrganizationPayload: Schema.Struct<{
  readonly organizationId: Schema.NullOr<Schema.String>;
}>;
```

## SetActiveOrganizationPayload (type alias)

**Signature**

```ts
export type SetActiveOrganizationPayload = typeof SetActiveOrganizationPayload.Type;
```

## SignInPayload

Request body for sign-in.

**Signature**

```ts
export declare const SignInPayload: Schema.Struct<{
  readonly email: Schema.String;
  readonly password: Schema.String;
  readonly captchaToken: Schema.optional<Schema.String>;
}>;
```

## SignInPayload (type alias)

**Signature**

```ts
export type SignInPayload = typeof SignInPayload.Type;
```

## SignUpPayload

Request body for sign-up.

**Signature**

```ts
export declare const SignUpPayload: Schema.Struct<{
  readonly email: Schema.String;
  readonly password: Schema.String;
  readonly name: Schema.optional<Schema.String>;
  readonly attributes: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
  readonly captchaToken: Schema.optional<Schema.String>;
}>;
```

## SignUpPayload (type alias)

**Signature**

```ts
export type SignUpPayload = typeof SignUpPayload.Type;
```

## SsoCallbackPayload

Request body for completing an SSO callback.

**Signature**

```ts
export declare const SsoCallbackPayload: Schema.Struct<{
  readonly state: Schema.String;
  readonly code: Schema.String;
}>;
```

## SsoCallbackPayload (type alias)

**Signature**

```ts
export type SsoCallbackPayload = typeof SsoCallbackPayload.Type;
```

## SsoProviderView

Public view of an SSO connection (never exposes the client secret).

**Signature**

```ts
export declare const SsoProviderView: Schema.Struct<{
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
}>;
```

## SsoProviderView (type alias)

**Signature**

```ts
export type SsoProviderView = typeof SsoProviderView.Type;
```

## SsoRegisterPayload

Request body for registering an SSO connection (admin-gated).

**Signature**

```ts
export declare const SsoRegisterPayload: Schema.Struct<{
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
}>;
```

## SsoRegisterPayload (type alias)

**Signature**

```ts
export type SsoRegisterPayload = typeof SsoRegisterPayload.Type;
```

## SsoSignInPayload

Request body for starting an SSO sign-in (any one of the fields).

**Signature**

```ts
export declare const SsoSignInPayload: Schema.Struct<{
  readonly email: Schema.optional<Schema.String>;
  readonly domain: Schema.optional<Schema.String>;
  readonly providerId: Schema.optional<Schema.String>;
}>;
```

## SsoSignInPayload (type alias)

**Signature**

```ts
export type SsoSignInPayload = typeof SsoSignInPayload.Type;
```

## SsoUrlView

The IdP authorization URL to redirect the user to, with its CSRF state.

**Signature**

```ts
export declare const SsoUrlView: Schema.Struct<{
  readonly url: Schema.String;
  readonly state: Schema.String;
}>;
```

## SsoUrlView (type alias)

**Signature**

```ts
export type SsoUrlView = typeof SsoUrlView.Type;
```

## StatusResponse

Generic acknowledgement for operations that intentionally do not reveal
outcome details (e.g. anti-enumeration email flows).

**Signature**

```ts
export declare const StatusResponse: Schema.Struct<{ readonly status: Schema.Boolean }>;
```

## StatusResponse (type alias)

**Signature**

```ts
export type StatusResponse = typeof StatusResponse.Type;
```

## TwoFactorConfirmPayload

Request body for confirming two-factor enrollment with a TOTP code.

**Signature**

```ts
export declare const TwoFactorConfirmPayload: Schema.Struct<{ readonly code: Schema.String }>;
```

## TwoFactorConfirmPayload (type alias)

**Signature**

```ts
export type TwoFactorConfirmPayload = typeof TwoFactorConfirmPayload.Type;
```

## TwoFactorEnableView

Result of enabling two-factor. The secret and backup codes are returned in
plaintext exactly once - show them to the user, then discard.

**Signature**

```ts
export declare const TwoFactorEnableView: Schema.Struct<{
  readonly secret: Schema.String;
  readonly totpUri: Schema.String;
  readonly backupCodes: Schema.$Array<Schema.String>;
}>;
```

## TwoFactorEnableView (type alias)

**Signature**

```ts
export type TwoFactorEnableView = typeof TwoFactorEnableView.Type;
```

## TwoFactorPasswordPayload

Request body for two-factor operations that re-verify the user's password
(enable, disable, regenerate backup codes).

**Signature**

```ts
export declare const TwoFactorPasswordPayload: Schema.Struct<{ readonly password: Schema.String }>;
```

## TwoFactorPasswordPayload (type alias)

**Signature**

```ts
export type TwoFactorPasswordPayload = typeof TwoFactorPasswordPayload.Type;
```

## TwoFactorVerifyPayload

Request body for redeeming a pending second-factor challenge: the challenge
`token` (from sign-in's `secondFactor`) plus a TOTP or backup `code`.

**Signature**

```ts
export declare const TwoFactorVerifyPayload: Schema.Struct<{
  readonly token: Schema.String;
  readonly code: Schema.String;
}>;
```

## TwoFactorVerifyPayload (type alias)

**Signature**

```ts
export type TwoFactorVerifyPayload = typeof TwoFactorVerifyPayload.Type;
```

## Unauthorized (class)

401 — missing/invalid credentials or session.

**Signature**

```ts
export declare class Unauthorized
```

## UnauthorizedError

Each error class paired with its HTTP status for use in endpoint `error` fields.

**Signature**

```ts
export declare const UnauthorizedError: Schema.decodeTo<
  Schema.declareConstructor<
    Unauthorized,
    { readonly message: string; readonly _tag: "Unauthorized" },
    readonly [Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>],
    { readonly message: string; readonly _tag: "Unauthorized" }
  >,
  Schema.TaggedStruct<"Unauthorized", { readonly message: Schema.String }>,
  never,
  never
>;
```

## UpdateMemberRolePayload

Request body for updating a member's role.

**Signature**

```ts
export declare const UpdateMemberRolePayload: Schema.Struct<{
  readonly userId: Schema.String;
  readonly role: Schema.String;
}>;
```

## UpdateMemberRolePayload (type alias)

**Signature**

```ts
export type UpdateMemberRolePayload = typeof UpdateMemberRolePayload.Type;
```

## UpdateOrganizationPayload

Request body for updating an organization.

**Signature**

```ts
export declare const UpdateOrganizationPayload: Schema.Struct<{
  readonly name: Schema.optional<Schema.String>;
  readonly slug: Schema.optional<Schema.String>;
  readonly logo: Schema.optional<Schema.String>;
  readonly metadata: Schema.optional<Schema.$Record<Schema.String, Schema.Unknown>>;
}>;
```

## UpdateOrganizationPayload (type alias)

**Signature**

```ts
export type UpdateOrganizationPayload = typeof UpdateOrganizationPayload.Type;
```

## UpdateUserPayload

Request body for updating the authenticated user's profile.

**Signature**

```ts
export declare const UpdateUserPayload: Schema.Struct<{
  readonly name: Schema.optional<Schema.String>;
  readonly image: Schema.optional<Schema.String>;
}>;
```

## UpdateUserPayload (type alias)

**Signature**

```ts
export type UpdateUserPayload = typeof UpdateUserPayload.Type;
```

## UserView

Public view of a user (timestamps as epoch millis).

**Signature**

```ts
export declare const UserView: Schema.Struct<{
  readonly id: Schema.String;
  readonly email: Schema.String;
  readonly emailVerified: Schema.Boolean;
  readonly name: Schema.optional<Schema.String>;
  readonly image: Schema.optional<Schema.String>;
  readonly createdAt: Schema.Number;
  readonly updatedAt: Schema.Number;
  readonly attributes: Schema.$Record<Schema.String, Schema.Unknown>;
}>;
```

## UserView (type alias)

**Signature**

```ts
export type UserView = typeof UserView.Type;
```

## UsernameSignInPayload

Request body for signing in with a username + password.

**Signature**

```ts
export declare const UsernameSignInPayload: Schema.Struct<{
  readonly username: Schema.String;
  readonly password: Schema.String;
}>;
```

## UsernameSignInPayload (type alias)

**Signature**

```ts
export type UsernameSignInPayload = typeof UsernameSignInPayload.Type;
```

## VerifyEmailPayload

Request body for verifying an email with a token.

**Signature**

```ts
export declare const VerifyEmailPayload: Schema.Struct<{ readonly token: Schema.String }>;
```

## VerifyEmailPayload (type alias)

**Signature**

```ts
export type VerifyEmailPayload = typeof VerifyEmailPayload.Type;
```

## encodeSession

**Signature**

```ts
export declare const encodeSession: (session: Types.Session) => SessionView;
```

## encodeSessionWithUser

**Signature**

```ts
export declare const encodeSessionWithUser: (value: Types.SessionWithUser) => SessionWithUserView;
```

## encodeUser

**Signature**

```ts
export declare const encodeUser: (user: Types.User) => UserView;
```
