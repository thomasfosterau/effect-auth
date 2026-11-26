/**
 * The BetterAuth instance, typed by the slice this package calls, and the one
 * module that reads `auth.$context` (BetterAuth's internal adapter, tables and
 * cookie names).
 *
 * @since 0.1.0
 */
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";

/**
 * A column's value in a BetterAuth row: core, plugin and `additionalFields`
 * columns alike.
 *
 * @since 0.1.0
 * @category models
 */
export type ColumnValue =
  | string
  | number
  | boolean
  | Date
  | null
  | undefined
  | ReadonlyArray<ColumnValue>
  | { readonly [key: string]: ColumnValue };

/**
 * The columns a write sets.
 *
 * @since 0.1.0
 * @category models
 */
export type Columns = Readonly<Record<string, ColumnValue>>;

/**
 * A row of BetterAuth's `user` table, as its server API and internal adapter
 * answer it. Plugins and `additionalFields` add further columns.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthUser {
  readonly id: string;
  readonly name?: string | null | undefined;
  readonly email?: string | null | undefined;
  readonly emailVerified?: boolean | null | undefined;
  readonly image?: string | null | undefined;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly [column: string]: ColumnValue;
}

/**
 * A row of BetterAuth's `session` table. `token` is the bearer credential and
 * never leaves this package; `id` is the stored id.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthSession {
  readonly id: string;
  readonly token: string;
  readonly userId: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly [column: string]: ColumnValue;
}

/**
 * A session and its user, as `getSession` and `findSession` answer them.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthSessionWithUser {
  readonly session: BetterAuthSession;
  readonly user: BetterAuthUser;
}

/**
 * A server API call's answer under `returnHeaders: true`.
 *
 * @since 0.1.0
 * @category models
 */
export interface WithHeaders<A> {
  readonly headers: Headers;
  readonly response: A;
}

/**
 * A sign-up or sign-in's answer. `token` is `null` for a sign-up that waits
 * for email verification; BetterAuth's `twoFactor()` plugin answers
 * `{ twoFactorRedirect: true }` for a sign-in it holds for the second factor.
 *
 * @since 0.1.0
 * @category models
 */
export type SignInAnswer =
  | { readonly token: string | null; readonly user: BetterAuthUser }
  | { readonly twoFactorRedirect: true };

/**
 * The `auth.api` endpoints this package calls. `signInUsername` exists only
 * with BetterAuth's `username()` plugin.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthApi {
  getSession(context: {
    headers: Headers;
    returnHeaders: true;
  }): Promise<WithHeaders<BetterAuthSessionWithUser | null>>;
  signUpEmail(context: {
    body: { email: string; password: string; name: string };
    headers: Headers;
    returnHeaders: true;
  }): Promise<WithHeaders<SignInAnswer>>;
  signInEmail(context: {
    body: { email: string; password: string; rememberMe?: boolean };
    headers: Headers;
    returnHeaders: true;
  }): Promise<WithHeaders<SignInAnswer>>;
  signInUsername?(context: {
    body: { username: string; password: string; rememberMe?: boolean };
    headers: Headers;
    returnHeaders: true;
  }): Promise<WithHeaders<SignInAnswer | null>>;
  signOut(context: {
    headers: Headers;
    returnHeaders: true;
  }): Promise<WithHeaders<{ success: boolean }>>;
}

/**
 * The internal-adapter methods this package calls. They act by user id or
 * token, with no request: BetterAuth's `auth.api` has no such call that works
 * without the acting user's headers.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthInternalAdapter {
  findSession(token: string): Promise<BetterAuthSessionWithUser | null>;
  listSessions(userId: string): Promise<ReadonlyArray<BetterAuthSession>>;
  deleteSession(token: string): Promise<void>;
  deleteSessions(tokens: Array<string>): Promise<void>;
  deleteUserSessions(userId: string): Promise<void>;
  updateSession(token: string, data: Columns): Promise<BetterAuthSession | null>;
  findUserById(userId: string): Promise<BetterAuthUser | null>;
  findUserByEmail(email: string): Promise<{ user: BetterAuthUser } | null>;
  updateUser(userId: string, data: Columns): Promise<BetterAuthUser | null>;
  deleteUser(userId: string): Promise<void>;
}

/**
 * BetterAuth's database adapter, for the lookups the internal adapter has no
 * method for (a session by its stored id, a user by username or phone).
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthAdapter {
  findOne<T>(query: {
    model: string;
    where: Array<{ field: string; value: string }>;
  }): Promise<T | null>;
}

/**
 * A column BetterAuth declares on a model, by the one property read here.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthField {
  readonly type: string | ReadonlyArray<string>;
}

/**
 * The resolved `auth.$context`, by the fields this package reads.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthContext {
  readonly internalAdapter: BetterAuthInternalAdapter;
  readonly adapter: BetterAuthAdapter;
  readonly tables: Readonly<
    Record<string, { readonly fields: Readonly<Record<string, BetterAuthField>> } | undefined>
  >;
  readonly authCookies: {
    readonly sessionToken: {
      readonly name: string;
      readonly attributes: { readonly secure?: boolean | undefined; readonly path?: string };
    };
  };
}

/**
 * A BetterAuth instance, structurally: what `betterAuth({ … })` returns, with
 * or without plugins.
 *
 * @since 0.1.0
 * @category models
 */
export interface BetterAuthLike {
  readonly api: BetterAuthApi;
  readonly $context: Promise<BetterAuthContext>;
}

/**
 * The BetterAuth instance and its resolved context, which every layer in this
 * package is built from.
 *
 * @since 0.1.0
 * @category services
 */
export class BetterAuthInstance extends Context.Service<
  BetterAuthInstance,
  {
    readonly api: BetterAuthApi;
    readonly context: BetterAuthContext;
  }
>()("@effect-auth/better-auth/BetterAuthInstance") {
  /**
   * Resolve `auth.$context` once. A failure to initialise (a bad adapter, a
   * missing secret) fails the layer with `AuthError`.
   */
  static readonly layer = (auth: BetterAuthLike): Layer.Layer<BetterAuthInstance, Auth.AuthError> =>
    Layer.effect(
      BetterAuthInstance,
      Effect.map(
        Effect.tryPromise({
          try: () => auth.$context,
          catch: (cause) =>
            new Auth.AuthError({ message: "BetterAuth failed to initialise", cause }),
        }),
        (context) => ({ api: auth.api, context }),
      ),
    );
}

/**
 * The columns BetterAuth declares for a model (core, plugin and
 * `additionalFields` columns), excluding `id`.
 *
 * @internal
 */
export const columnsOf = (context: BetterAuthContext, model: string): ReadonlyArray<string> =>
  R.keys(context.tables[model]?.fields ?? {});

/**
 * Run an internal-adapter or database call, mapping a rejection to
 * `AuthError` with the cause kept.
 *
 * @internal
 */
export const adapterCall = <A>(
  operation: string,
  run: () => Promise<A>,
): Effect.Effect<A, Auth.AuthError> =>
  Effect.tryPromise({
    try: run,
    catch: (cause) => new Auth.AuthError({ message: `BetterAuth ${operation} failed`, cause }),
  });
