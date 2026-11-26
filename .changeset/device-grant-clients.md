---
"@thomasfosterau/effect-auth": minor
---

Bind the device authorization grant to registered clients and the scopes they ask for. **Breaking:**

- `DeviceAuthorizationConfig` takes a required `clients` list (`DeviceClient`: `id`, `name`, `scopes`). `begin` takes a required `clientId`, and `POST /device/code` refuses an unknown client with `invalid_client` and a scope the client is not registered for with `invalid_scope` (each the `message` of a `400`). A request whose client is removed later can no longer be looked up, approved or redeemed.
- The verification page looks a code up before the user decides: `DeviceAuthorizationService.lookup` and `POST /device-authorizations/lookups` answer the client's id and name, the requested scopes and the status, as a `device-authorizations` resource named by the device code's digest. `POST /device-authorizations/decisions` now answers `200` with that resource instead of `204`, and `approve` / `deny` return it.
- Denying needs a session, as approving does; `deny(userCode, userId)` records who denied. Lookups and decisions are limited to 10 per signed-in caller per 15 minutes, one bucket per caller instead of one per guessed code, beside a per-address rule for `/device-authorizations/lookups`.
- The session a device receives records the grant under `attributes.deviceGrant` (`{ clientId, scopes }`), which `deviceGrantOf(session)` reads, so an app can restrict what a device session may do. `DevicePollResult` carries it as `grant`.
- `DeviceAuthorizationStore` replaces `update` with two conditional writes: `settle(userCode, decision, now)` records a decision only on a pending, unexpired request, and `touch(deviceCode, { lastPolledAt } | { interval })` writes only that field and returns the current record. A poll racing a decision can no longer write a stale status back, and a denial can no longer become an approval. `memoryDeviceAuthorizationStore` in `/testing` is the reference implementation.
- The browser client gains `device.lookup`; `device.code` requires its payload, and `device.approve` / `device.deny` resolve to the `DeviceAuthorizationView`. `./client/testing` registers `FIXTURE_DEVICE_CLIENT`.
