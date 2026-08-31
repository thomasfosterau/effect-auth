<!--
  One labelled input: the `<label for>` / `<input id>` pair every bundled form
  is built from. Internal to the package.
-->
<script lang="ts">
  import type { ResolvedClasses } from "./internal.ts";

  interface Props {
    classes: ResolvedClasses;
    id: string;
    name: string;
    type: "email" | "password" | "text";
    /** The browser's autofill hint; every form sets a real one. */
    autocomplete: "email" | "username" | "name" | "current-password" | "new-password" | "one-time-code";
    label: string;
    value: string;
    onValueChange: (value: string) => void;
    invalid: boolean;
    disabled: boolean;
    inputmode?: "numeric" | undefined;
    /** Defaults to `true`; pass `false` for genuinely optional inputs. */
    required?: boolean;
  }

  const {
    classes,
    id,
    name,
    type,
    autocomplete,
    label,
    value,
    onValueChange,
    invalid,
    disabled,
    inputmode = undefined,
    required = true,
  }: Props = $props();
</script>

<div class={classes.field}>
  <label class={classes.label} for={id}>{label}</label>
  <input
    {id}
    {name}
    {type}
    {autocomplete}
    {required}
    {disabled}
    {inputmode}
    {value}
    class={classes.input}
    aria-invalid={invalid ? "true" : undefined}
    oninput={(event) => onValueChange(event.currentTarget.value)}
  />
</div>
