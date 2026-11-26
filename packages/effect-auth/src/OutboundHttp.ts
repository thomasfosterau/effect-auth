/**
 * The core's outbound requests (remote JWKS, the Cloudflare Access keys, the
 * OAuth and OIDC provider endpoints) go through Effect's `HttpClient`, which
 * the application provides (`FetchHttpClient.layer` on Workers, in browsers
 * and on Node).
 */
import { Effect } from "effect";
import {
  type HttpClient,
  type HttpClientError,
  HttpClientRequest,
  type HttpClientResponse,
} from "effect/http";

/** A `GET` that asks for JSON. */
export const getJson = (url: string): HttpClientRequest.HttpClientRequest =>
  HttpClientRequest.get(url).pipe(HttpClientRequest.acceptJson);

/** Send `request` through `client`. */
export const send = (
  client: HttpClient.HttpClient,
  request: HttpClientRequest.HttpClientRequest,
): Effect.Effect<HttpClientResponse.HttpClientResponse, HttpClientError.HttpClientError> =>
  client.execute(request);

/** Whether a response is a 2xx. */
export const isOk = (response: HttpClientResponse.HttpClientResponse): boolean =>
  response.status >= 200 && response.status < 300;
