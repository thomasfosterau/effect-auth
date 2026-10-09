---
"@thomasfosterau/effect-auth-solid": minor
---

Raise the `solid-js` peer floor from `>=1.8` to `>=1.9.17` (#308).

solid-js 1.9.15 and earlier declare `seroval` and `seroval-plugins` `~1.5.4`, inside the range covered by GHSA-p6vx-979v-rg4c and GHSA-jp82-f5mq-hwhp. A consumer on one of those releases resolves that seroval in its own dependency tree, which no override in this workspace can change. solid-js 1.9.16 moved to `seroval ~1.6.8`; the floor is set at 1.9.17, the release this workspace now builds against. No API changes.
