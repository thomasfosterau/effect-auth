<!--
  The `role="alert"` failure and optional `role="status"` success elements every
  bundled form renders. Internal to the package.
-->
<script lang="ts">
  import * as Option from "effect/Option";
  import type { FormFailure, ResolvedClasses } from "./internal.ts";

  interface Props {
    classes: ResolvedClasses;
    failure: Option.Option<FormFailure>;
    succeeded?: boolean;
    successMessage?: string;
  }

  const {
    classes,
    failure,
    succeeded = false,
    successMessage = undefined,
  }: Props = $props();
</script>

{#if Option.isSome(failure)}
  <p class={classes.error} role="alert">{failure.value.message}</p>
{/if}
{#if succeeded && successMessage !== undefined}
  <p class={classes.status} role="status">{successMessage}</p>
{/if}
