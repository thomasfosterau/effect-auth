<!--
  The `role="alert"` failure and optional `role="status"` success elements every
  bundled form renders. Internal to the package.
-->
<script lang="ts">
  import type { FormFailure, ResolvedClasses } from "./internal.ts";

  interface Props {
    classes: ResolvedClasses;
    failure: FormFailure | null;
    succeeded?: boolean;
    successMessage?: string | undefined;
  }

  const {
    classes,
    failure,
    succeeded = false,
    successMessage = undefined,
  }: Props = $props();
</script>

{#if failure !== null}
  <p class={classes.error} role="alert">{failure.message}</p>
{/if}
{#if succeeded && successMessage !== undefined}
  <p class={classes.status} role="status">{successMessage}</p>
{/if}
