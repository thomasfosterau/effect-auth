<!--
  The submit button, disabled and relabelled while the form is pending.
  Internal to the package.
-->
<script lang="ts">
  import type { ResolvedClasses } from "./internal.ts";

  interface Props {
    classes: ResolvedClasses;
    pending: boolean;
    label: string;
    pendingLabel: string;
  }

  const { classes, pending, label, pendingLabel }: Props = $props();
</script>

<button class={classes.submit} disabled={pending} type="submit">
  {pending ? pendingLabel : label}
</button>
