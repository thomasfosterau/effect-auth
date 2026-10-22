---
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-alchemy": minor
---

`purgeExpired` deletes the magic-link and email-OTP rows whose expiry has passed and reports how many it deleted from each table. No store deletes them on its own, and the sends that hide whether an account exists write one for any address, so a host schedules this (a cron trigger on Workers, a timer on a long-lived server) to keep the tables bounded. effect-auth-sql exports it over the ambient `SqlClient`; effect-auth-alchemy exports `purgeExpired(db)` over a D1 binding. The schema gains an `expires_at` index on each of the two tables, which `migrate` adds on the next run (#420).
