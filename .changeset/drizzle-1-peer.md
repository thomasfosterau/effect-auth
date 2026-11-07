---
"@thomasfosterau/effect-auth-drizzle": patch
---

Admit drizzle-orm's 1.0 line in the `drizzle-orm` peer range: `>=0.44.0 || >=1.0.0-rc.5` (was `>=0.44.0`, which rejects every 1.0 release candidate, since a range never matches a prerelease it does not name). The package's suite now runs on both lines, 0.45 and 1.0.0-rc.5 (#544).

The README and API examples now hand drivers their client as `drizzle({ client })`: drizzle-orm 1.0 reads a bare client argument as a config and opens a default connection in its place.
