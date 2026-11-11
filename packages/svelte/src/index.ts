/**
 * Svelte bindings for the effect-auth client.
 *
 * The session is an `effect/reactivity` Atom graph
 * (`makeSessionAtoms` from `@thomasfosterau/effect-auth/client/atoms`), read
 * through the application's own `AtomRegistry`. This package adapts Atoms to
 * Svelte's readable-store contract, so they work with the `$store` syntax
 * without importing `svelte/store`:
 *
 * ```svelte
 * <script>
 *   const session = sessionStore(registry, auth);
 * </script>
 * {#if $session.data}Signed in as {$session.data.user.email}{/if}
 * ```
 *
 * {@link atomStore} is the whole Svelte↔Atom binding, over any Atom: the
 * session stores are it applied to the session Atoms. It is small enough to
 * live here until a shared Svelte Atom binding takes it over.
 *
 * The bundled form components are the other half of the package: real,
 * unstyled `.svelte` components for sign-in, sign-up, password reset, magic
 * links and email one-time codes, each owning its own submit, pending and error
 * state and reaching the client through {@link setAuthClient}'s context.
 *
 * @module effect-auth-svelte
 */
import type {
  SessionAtoms,
  SessionListState,
  SessionState,
} from "@thomasfosterau/effect-auth/client/atoms";
import type { Atom, AtomRegistry } from "effect/reactivity";

export { authClientKey, getAuthClient, setAuthClient } from "./context.ts";

export { default as SignInForm } from "./forms/SignInForm.svelte";
export { default as SignUpForm } from "./forms/SignUpForm.svelte";
export { default as PasswordResetRequestForm } from "./forms/PasswordResetRequestForm.svelte";
export { default as PasswordResetConfirmForm } from "./forms/PasswordResetConfirmForm.svelte";
export { default as MagicLinkForm } from "./forms/MagicLinkForm.svelte";
export { default as EmailOtpForm } from "./forms/EmailOtpForm.svelte";

export type {
  AuthFormBaseProps,
  AuthFormClasses,
  AuthSuccess,
  EmailOtpPurpose,
  FormFailure,
  StatusResponse,
} from "./forms/internal.ts";
export type {
  EmailOtpFormProps,
  EmailOtpLabels,
  MagicLinkFormProps,
  MagicLinkLabels,
  PasswordResetConfirmFormProps,
  PasswordResetConfirmLabels,
  PasswordResetRequestFormProps,
  PasswordResetRequestLabels,
  SignInFormProps,
  SignInLabels,
  SignUpFormProps,
  SignUpLabels,
} from "./forms/props.ts";

/** Svelte's readable-store contract. */
export interface Readable<T> {
  readonly subscribe: (run: (value: T) => void) => () => void;
}

/**
 * An Atom as a Svelte readable store over `registry`. Subscribing mounts the
 * Atom and calls `run` at once with its value, then on every change;
 * unsubscribing unmounts it. No state is held here: the registry is the store.
 */
export const atomStore = <A>(
  registry: AtomRegistry.AtomRegistry,
  atom: Atom.Atom<A>,
): Readable<A> => ({
  subscribe: (run) => registry.subscribe(atom, run, { immediate: true }),
});

/**
 * The session as a readable store: `atoms.state` through {@link atomStore}.
 * The first subscription starts the session read; session-changing calls on
 * the client refetch it while it is subscribed.
 */
export const sessionStore = (
  registry: AtomRegistry.AtomRegistry,
  atoms: SessionAtoms,
): Readable<SessionState> => atomStore(registry, atoms.state);

/** The state {@link listSessionsStore} emits. */
export type ListSessionsState = SessionListState;

/** A readable store over the user's active sessions, with a refetch handle. */
export interface ListSessionsStore extends Readable<ListSessionsState> {
  /** Re-read the list (after revoking a session, say). */
  readonly refetch: () => void;
}

/**
 * The signed-in user's sessions as a readable store: `atoms.sessionsState`
 * through {@link atomStore}. The first subscription starts the read, a session
 * change refetches it through the Atom graph, and `refetch()` refreshes it.
 */
export const listSessionsStore = (
  registry: AtomRegistry.AtomRegistry,
  atoms: SessionAtoms,
): ListSessionsStore => ({
  ...atomStore(registry, atoms.sessionsState),
  refetch: () => registry.refresh(atoms.sessions),
});
