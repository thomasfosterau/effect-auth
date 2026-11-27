/**
 * The WorkOS REST client: Bearer-authenticated JSON requests to
 * `https://api.workos.com` through the core's `OutboundHttp.send` (one
 * timeout, a body cap, no redirects), each in a span that names the method and
 * path template only. The API key never reaches an error, a span or a log.
 *
 * @since 0.1.0
 */
import * as Config from "effect/Config";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";
import { ErrorBody } from "./Schemas.ts";

/**
 * How the package reaches WorkOS and seals its cookie.
 *
 * @since 0.1.0
 * @category models
 */
export interface WorkOSConfig {
  /** The environment's secret API key (`sk_…`). */
  readonly apiKey: Redacted.Redacted;
  /** The AuthKit client id (`client_…`). */
  readonly clientId: string;
  /**
   * The password the session cookie is sealed with: at least 32 bytes. Keys
   * derived from it are named by a key id, so a password listed in
   * `previousCookiePasswords` still opens the cookies it sealed.
   */
  readonly cookiePassword: Redacted.Redacted;
  /** Earlier cookie passwords, still accepted when opening a cookie. */
  readonly previousCookiePasswords?: ReadonlyArray<Redacted.Redacted>;
  /** The API origin (default `https://api.workos.com`). */
  readonly baseUrl?: string;
  /**
   * The `iss` an access token must carry (default
   * `<baseUrl>/user_management/<clientId>`). An environment on a custom
   * AuthKit domain names that domain here.
   */
  readonly issuer?: string;
  /** Where AuthKit and SSO send the browser back with a code. */
  readonly redirectUri?: string;
  /**
   * Who sends Magic Auth codes and password-reset links: WorkOS from its
   * dashboard templates (`"workos"`, the default), or the app through the
   * core `EmailSender` (`"app"`), with the code or token WorkOS answers. Turn
   * WorkOS's own email for those off in the dashboard for `"app"`.
   */
  readonly delivery?: "workos" | "app";
  /**
   * How long a session cookie lives, in milliseconds, from the sign-in
   * (default 30 days). Match the session lifetime set in the WorkOS
   * dashboard: WorkOS refuses a refresh past it whatever the cookie says.
   */
  readonly sessionMaxAge?: number;
  /** Clock tolerance for access-token `exp`, in milliseconds (default 30 s). */
  readonly clockSkewLeeway?: number;
}

/**
 * {@link WorkOSConfig} with its defaults applied.
 *
 * @since 0.1.0
 * @category models
 */
export interface ResolvedConfig {
  readonly apiKey: Redacted.Redacted;
  readonly clientId: string;
  readonly cookiePasswords: ReadonlyArray<Redacted.Redacted>;
  readonly baseUrl: string;
  readonly issuer: string;
  readonly redirectUri: Option.Option<string>;
  readonly delivery: "workos" | "app";
  readonly sessionMaxAge: number;
  readonly clockSkewLeeway: number;
}

const DAY = 24 * 60 * 60 * 1000;

/**
 * Apply the defaults to a {@link WorkOSConfig}.
 *
 * @since 0.1.0
 * @category constructors
 */
export const resolveConfig = (options: WorkOSConfig): ResolvedConfig => {
  const baseUrl = (options.baseUrl ?? "https://api.workos.com").replace(/\/+$/, "");
  return {
    apiKey: options.apiKey,
    clientId: options.clientId,
    cookiePasswords: [options.cookiePassword, ...(options.previousCookiePasswords ?? [])],
    baseUrl,
    // TODO(#900): the default issuer is from memory of the AuthKit docs; check
    // it against a live access token before the package is published.
    issuer: options.issuer ?? `${baseUrl}/user_management/${options.clientId}`,
    redirectUri: Option.fromUndefinedOr(options.redirectUri),
    delivery: options.delivery ?? "workos",
    sessionMaxAge: options.sessionMaxAge ?? 30 * DAY,
    clockSkewLeeway: options.clockSkewLeeway ?? 30_000,
  };
};

const fromEnvironment = (values: {
  readonly apiKey: Redacted.Redacted;
  readonly clientId: string;
  readonly cookiePassword: Redacted.Redacted;
  readonly redirectUri: Option.Option<string>;
  readonly issuer: Option.Option<string>;
}): WorkOSConfig => ({
  apiKey: values.apiKey,
  clientId: values.clientId,
  cookiePassword: values.cookiePassword,
  ...Option.match(values.redirectUri, {
    onNone: () => ({}),
    onSome: (redirectUri) => ({ redirectUri }),
  }),
  ...Option.match(values.issuer, { onNone: () => ({}), onSome: (issuer) => ({ issuer }) }),
});

/**
 * The {@link WorkOSConfig} from the environment: `WORKOS_API_KEY`,
 * `WORKOS_CLIENT_ID`, `WORKOS_COOKIE_PASSWORD`, and optionally
 * `WORKOS_REDIRECT_URI` and `WORKOS_ISSUER`.
 *
 * @since 0.1.0
 * @category config
 */
export const config: Config.Config<WorkOSConfig> = Config.all({
  apiKey: Config.Redacted("WORKOS_API_KEY"),
  clientId: Config.String("WORKOS_CLIENT_ID"),
  cookiePassword: Config.Redacted("WORKOS_COOKIE_PASSWORD"),
  redirectUri: Config.option(Config.String("WORKOS_REDIRECT_URI")),
  issuer: Config.option(Config.String("WORKOS_ISSUER")),
}).pipe(Config.map(fromEnvironment));

/**
 * A WorkOS request that did not succeed: a non-2xx answer (`status`, WorkOS's
 * `code`, its `x-request-id`), or a request that could not complete
 * (`status: 0`). The body stays out of it: WorkOS echoes input there.
 *
 * @since 0.1.0
 * @category errors
 */
export class WorkOSError extends Schema.TaggedError<
  WorkOSError,
  { readonly brand: unique symbol }
>()("WorkOSError", {
  message: Schema.String,
  status: Schema.Finite,
  code: Schema.optionalKey(Schema.String),
  requestId: Schema.optionalKey(Schema.String),
  /** The pending-authentication token an `email_verification_required` answer carries. */
  pendingAuthenticationToken: Schema.optionalKey(Schema.String),
  cause: Schema.optionalKey(Schema.Unknown),
}) {}

/**
 * The `AuthError` for a failure no domain error describes, the
 * {@link WorkOSError} kept as its cause.
 *
 * @since 0.1.0
 * @category errors
 */
export const toAuthError = (error: WorkOSError): Auth.Errors.AuthError =>
  new Auth.Errors.AuthError({ message: `WorkOS request failed (${error.status})`, cause: error });

/**
 * The `AuthError` for a core method WorkOS has no equivalent of.
 *
 * @since 0.1.0
 * @category errors
 */
export const unsupported = (what: string): Auth.Errors.AuthError =>
  new Auth.Errors.AuthError({ message: `${what} is not supported by the WorkOS backend` });

/**
 * One request to WorkOS.
 *
 * @since 0.1.0
 * @category models
 */
export interface RequestOptions<S extends Schema.Top> {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  /** The path, ids already encoded (`path` builds one). */
  readonly path: string;
  /** The span's name for it, the path template (`/user_management/users/{id}`). */
  readonly route: string;
  readonly body?: Schema.JsonObject;
  readonly query?: Readonly<Record<string, string>>;
  /** The answer's schema; omit for an answer whose body is not read. */
  readonly schema?: S;
}

/**
 * The WorkOS client.
 *
 * @since 0.1.0
 * @category services
 */
export class WorkOSClient extends Context.Service<
  WorkOSClient,
  {
    readonly config: ResolvedConfig;
    /** Send `options` and decode the answer; a non-2xx is a {@link WorkOSError}. */
    readonly request: <S extends Schema.Top = typeof Schema.Unknown>(
      options: RequestOptions<S>,
    ) => Effect.Effect<S["Type"], WorkOSError, S["DecodingServices"]>;
  }
>()("@effect-auth/workos/WorkOSClient") {
  /** The client over the `HttpClient` in context, for a custom transport or a test. */
  static readonly layerHttpClient = (
    options: WorkOSConfig,
  ): Layer.Layer<WorkOSClient, never, HttpClient.HttpClient> =>
    Layer.effect(WorkOSClient, make(resolveConfig(options)));

  /** The client over the platform `fetch` (`FetchHttpClient.Fetch` replaces it). */
  static readonly layer = (options: WorkOSConfig): Layer.Layer<WorkOSClient> =>
    WorkOSClient.layerHttpClient(options).pipe(Layer.provide(FetchHttpClient.layer));

  /** The client from {@link config}. */
  static readonly layerConfig: Layer.Layer<WorkOSClient, Config.ConfigError> = Layer.unwrap(
    Effect.gen(function* () {
      return WorkOSClient.layer(yield* config);
    }),
  );
}

/**
 * A path with each id URL-encoded, so an id cannot add a segment.
 *
 * @since 0.1.0
 * @category utils
 */
export const path = (strings: TemplateStringsArray, ...ids: ReadonlyArray<string>): string =>
  strings.reduce((out, part, i) => out + encodeURIComponent(ids[i - 1] ?? "") + part);

const decodeErrorBody = Schema.decodeUnknownOption(Schema.fromJsonString(ErrorBody));

const errorFrom = (status: number, body: string, requestId?: string): WorkOSError => {
  const fields = Option.getOrUndefined(decodeErrorBody(body));
  const code = fields?.code ?? fields?.error ?? fields?.errors?.[0]?.code ?? undefined;
  const pendingAuthenticationToken = fields?.pending_authentication_token ?? undefined;
  return new WorkOSError({
    message: `WorkOS answered ${status}${code === undefined ? "" : ` (${code})`}`,
    status,
    ...(code !== undefined && { code }),
    ...(requestId !== undefined && { requestId }),
    ...(pendingAuthenticationToken !== undefined && { pendingAuthenticationToken }),
  });
};

const make = (resolved: ResolvedConfig) =>
  Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const limits = yield* Auth.OutboundHttp.OutboundLimits;
    const request = <S extends Schema.Top = typeof Schema.Unknown>(options: RequestOptions<S>) =>
      Effect.gen(function* () {
        const url = new URL(resolved.baseUrl + options.path);
        url.search = new URLSearchParams(options.query ?? {}).toString();
        let req = HttpClientRequest.make(options.method)(url).pipe(
          HttpClientRequest.bearerToken(Redacted.value(resolved.apiKey)),
          HttpClientRequest.acceptJson,
        );
        if (options.body !== undefined) req = HttpClientRequest.bodyJsonUnsafe(req, options.body);
        const response = yield* Auth.OutboundHttp.send(client, req, limits).pipe(
          Effect.mapError((cause) => new WorkOSError({ message: cause.message, status: 0, cause })),
        );
        const requestId = response.headers["x-request-id"];
        if (response.status < 200 || response.status >= 300) {
          const error = errorFrom(response.status, response.body, requestId);
          yield* Effect.logDebug("WorkOS request refused").pipe(
            Effect.annotateLogs({
              route: options.route,
              status: `${error.status}`,
              code: error.code ?? "",
              requestId: requestId ?? "",
            }),
          );
          return yield* error;
        }
        const schema = options.schema;
        if (schema === undefined) return undefined;
        const json = yield* Auth.OutboundHttp.parseJson(
          response.body === "" ? "null" : response.body,
        );
        return yield* Schema.decodeUnknownEffect(schema)(json);
      }).pipe(
        Effect.catchTag("SchemaError", (cause) =>
          Effect.fail(
            new WorkOSError({
              message: `WorkOS answered a body this package cannot read (${options.route})`,
              status: 200,
              cause,
            }),
          ),
        ),
        Effect.withSpan(`workos ${options.method} ${options.route}`, {
          attributes: { "http.method": options.method, "http.route": options.route },
        }),
      );
    return WorkOSClient.of({ config: resolved, request });
  });
