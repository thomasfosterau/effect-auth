---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-client": minor
---

**Breaking (HTTP):** the included HTTP API starts speaking JSON:API (#205). The session, identifier and own-profile endpoints are now JSON:API resources, answering `application/vnd.api+json` documents and JSON:API error documents:

| Before                              | Now                                                  |
| ----------------------------------- | ---------------------------------------------------- |
| `GET /session`                      | `GET /sessions/current?include=user`                 |
| `POST /sign-out`                    | `DELETE /sessions/current`                           |
| `GET /sessions`                     | `GET /sessions` (a collection document)              |
| `DELETE /sessions/:sessionId`       | `DELETE /sessions/:id`, `id` the listed (hashed) id  |
| `POST /sessions/revoke-others`      | `DELETE /sessions?filter[current]=false`             |
| `GET /identifiers`                  | `GET /identifiers` (the identifier's type is `kind`) |
| `DELETE /identifiers/:identifierId` | `DELETE /identifiers/:id`                            |
| `PATCH /user`                       | `PATCH /users/me` (a JSON:API update document)       |

- A session is now revoked by the id `GET /sessions` lists (the hash of its token). Before, the endpoint took the raw token, so a listed session other than your own could not be revoked. `SessionService` gains `revokeSessionById(userId, storedSessionId)` for it.
- A foreign or unknown session or identifier answers `404` (was `400`); removing an account's last identifier answers `403` (was `400`).
- `PATCH /users/me` accepts only `name` and `image`; a write to the `attributes` bag is refused (`400`, #193).
- `@thomasfosterau/effect-jsonapi` is an optional peer of effect-auth, needed only by the `./http` subpath. New in `./http`: `Http.Resources` (the resource declarations), `Http.JsonApiErrors` (the error documents), `Http.groupLayers` (every group plus the JSON:API middleware, for serving `AuthApi` from your own `HttpApiBuilder`; compose it in place of `authGroupLayer` + `scimGroupLayer`) and `Http.RemoteSession.fromSessionDocument`.
- `RemoteSession` reads `GET /sessions/current?include=user`, so an app and its auth service must be on the same release.

effect-auth-client keeps its method signatures and maps the documents onto the same view types. `revokeSession(id)` now takes the id `listSessions()` reports, and an error's `message` is read from a JSON:API error document's `detail`.
