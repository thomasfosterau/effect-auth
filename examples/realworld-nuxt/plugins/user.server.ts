/**
 * Make the SSR-resolved user available to all client components via
 * a `useState('user')` shared composable. The server middleware
 * populates `event.context.user`; this plugin copies it to a
 * reactive Nuxt state so layouts can render the nav correctly on
 * first paint and reuse the value on the client.
 */
export default defineNuxtPlugin(() => {
  const event = useRequestEvent();
  const user = useState<import("../server/types").ConduitProfile | null>("user", () => null);
  if (event) user.value = event.context.user ?? null;
});
