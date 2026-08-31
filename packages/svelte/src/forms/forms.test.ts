import { describe, it, expect } from "vite-plus/test";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { authClientKey } from "../context.ts";
import EmailOtpForm from "./EmailOtpForm.svelte";
import MagicLinkForm from "./MagicLinkForm.svelte";
import PasswordResetConfirmForm from "./PasswordResetConfirmForm.svelte";
import PasswordResetRequestForm from "./PasswordResetRequestForm.svelte";
import SignInForm from "./SignInForm.svelte";
import SignUpForm from "./SignUpForm.svelte";
import type { AuthSuccess, StatusResponse } from "./internal.ts";

const EMAIL = "alice@svelte.test";
const PW = "password-123";

const now = Date.now();
const authSuccess = {
  user: { id: "user-1", email: EMAIL, createdAt: now, updatedAt: now, attributes: {} },
  needsEmailVerification: false,
} as unknown as AuthSuccess;
const ok: StatusResponse = { status: true };

/**
 * Only the handful of methods a given form touches are stubbed: these tests are
 * about the components, and the client package has its own suite for the
 * requests themselves.
 */
const stub = (methods: object): AuthClient => methods as unknown as AuthClient;

/** Put a client in Svelte context, the way `setAuthClient` does. */
const withClient = (client: AuthClient) => new Map<unknown, unknown>([[authClientKey, client]]);

/** A promise plus the handles to settle it, for holding a form pending. */
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
};

const formOf = (container: HTMLElement): HTMLFormElement => {
  const form = container.querySelector("form");
  if (form === null) throw new Error("the component rendered no <form>");
  return form;
};

/** Type into a labelled input. */
const type = (label: string | RegExp, value: string) =>
  fireEvent.input(screen.getByLabelText(label), { target: { value } });

describe("SignInForm", () => {
  it("signs in with the email in context's client and fires onSuccess", async () => {
    const calls: unknown[] = [];
    const seen: AuthSuccess[] = [];
    const client = stub({
      signIn: (payload: unknown) => {
        calls.push(payload);
        return Promise.resolve(authSuccess);
      },
    });

    const { container } = render(SignInForm, {
      props: { onSuccess: (result: AuthSuccess) => seen.push(result) },
      context: withClient(client),
    });

    await type("Email", EMAIL);
    await type("Password", PW);
    await fireEvent.submit(formOf(container));

    await waitFor(() => expect(calls).toEqual([{ email: EMAIL, password: PW }]));
    expect(seen).toEqual([authSuccess]);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("renders accessible markup with the documented class hooks", () => {
    const { container } = render(SignInForm, {
      props: { client: stub({}), class: "my-card" },
    });

    const form = formOf(container);
    expect(form.className).toBe("ea-form ea-sign-in my-card");
    expect(form.dataset["variant"]).toBe("email");
    expect(container.querySelectorAll(".ea-field").length).toBe(2);
    expect(screen.getByLabelText("Email").getAttribute("autocomplete")).toBe("email");
    expect(screen.getByLabelText("Password").getAttribute("autocomplete")).toBe("current-password");
    expect(screen.getByRole("button", { name: "Sign in" }).getAttribute("type")).toBe("submit");
  });

  it('switches to signInUsername under variant="username"', async () => {
    const calls: unknown[] = [];
    const client = stub({
      signInUsername: (payload: unknown) => {
        calls.push(payload);
        return Promise.resolve(authSuccess);
      },
      signIn: () => Promise.reject(new Error("the email method must not be used")),
    });

    const { container } = render(SignInForm, {
      props: { variant: "username", client },
    });

    const username = screen.getByLabelText("Username");
    expect(username.getAttribute("autocomplete")).toBe("username");
    await fireEvent.input(username, { target: { value: "alice" } });
    await type("Password", PW);
    await fireEvent.submit(formOf(container));

    await waitFor(() => expect(calls).toEqual([{ username: "alice", password: PW }]));
  });

  it('renders a role="alert" with the server\'s message and fires onError', async () => {
    const failure = new Error("Invalid email or password.");
    const seen: unknown[] = [];
    const { container } = render(SignInForm, {
      props: {
        client: stub({ signIn: () => Promise.reject(failure) }),
        onError: (e: unknown) => seen.push(e),
      },
    });

    await fireEvent.submit(formOf(container));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("Invalid email or password.");
    expect(alert.className).toBe("ea-error");
    expect(seen).toEqual([failure]);
    expect(screen.getByLabelText("Email").getAttribute("aria-invalid")).toBe("true");
  });

  it("falls back to the label copy when the failure carries no message", async () => {
    const { container } = render(SignInForm, {
      props: { client: stub({ signIn: () => Promise.reject(new Error("")) }) },
    });

    await fireEvent.submit(formOf(container));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("Sign-in failed. Please check your details and try again.");
  });

  it("disables the submit button and marks the form busy while pending", async () => {
    const gate = deferred<AuthSuccess>();
    const { container } = render(SignInForm, {
      props: { client: stub({ signIn: () => gate.promise }) },
    });

    const form = formOf(container);
    expect(form.getAttribute("aria-busy")).toBeNull();

    await fireEvent.submit(form);

    const button = screen.getByRole("button", { name: "Signing in…" });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(form.getAttribute("aria-busy")).toBe("true");
    expect((screen.getByLabelText("Email") as HTMLInputElement).disabled).toBe(true);

    gate.resolve(authSuccess);
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Sign in" }) as HTMLButtonElement).disabled).toBe(
        false,
      ),
    );
    expect(form.getAttribute("aria-busy")).toBeNull();
  });

  it("takes every visible string from the labels prop", () => {
    render(SignInForm, {
      props: { client: stub({}), labels: { email: "Work email", submit: "Continue" } },
    });

    screen.getByLabelText("Work email");
    screen.getByRole("button", { name: "Continue" });
    // Unspecified labels keep their defaults.
    screen.getByLabelText("Password");
  });

  it("throws when no client is in context and none is passed", () => {
    expect(() => render(SignInForm, { props: {} })).toThrow(/No auth client in context/);
  });
});

describe("SignUpForm", () => {
  it("omits a blank name and trims a filled one", async () => {
    const calls: unknown[] = [];
    const client = stub({
      signUp: (payload: unknown) => {
        calls.push(payload);
        return Promise.resolve(authSuccess);
      },
    });
    const { container } = render(SignUpForm, { props: {}, context: withClient(client) });

    expect(screen.getByLabelText("Password").getAttribute("autocomplete")).toBe("new-password");
    expect((screen.getByLabelText("Name") as HTMLInputElement).required).toBe(false);

    await type("Email", EMAIL);
    await type("Password", PW);
    await fireEvent.submit(formOf(container));
    await waitFor(() => expect(calls[0]).toEqual({ email: EMAIL, password: PW }));

    await type("Name", "  Alice  ");
    await fireEvent.submit(formOf(container));
    await waitFor(() => expect(calls[1]).toEqual({ email: EMAIL, password: PW, name: "Alice" }));
  });

  it("hides the name field under showName={false}", () => {
    render(SignUpForm, { props: { client: stub({}), showName: false } });
    expect(screen.queryByLabelText("Name")).toBeNull();
  });

  it('reports a failure through role="alert"', async () => {
    const { container } = render(SignUpForm, {
      props: { client: stub({ signUp: () => Promise.reject(new Error("Email already in use.")) }) },
    });

    await fireEvent.submit(formOf(container));
    expect((await screen.findByRole("alert")).textContent).toBe("Email already in use.");
  });
});

describe("PasswordResetRequestForm", () => {
  it('sends the email and renders a role="status" acknowledgement', async () => {
    const calls: unknown[] = [];
    const seen: StatusResponse[] = [];
    const client = stub({
      passwordResetRequest: (payload: unknown) => {
        calls.push(payload);
        return Promise.resolve(ok);
      },
    });

    const { container } = render(PasswordResetRequestForm, {
      props: { onSuccess: (result: StatusResponse) => seen.push(result) },
      context: withClient(client),
    });

    await type("Email", EMAIL);
    await fireEvent.submit(formOf(container));

    await waitFor(() => expect(calls).toEqual([{ email: EMAIL }]));
    expect(seen).toEqual([ok]);
    const status = await screen.findByRole("status");
    expect(status.textContent).toBe("If that email has an account, a reset link is on its way.");
  });
});

describe("PasswordResetConfirmForm", () => {
  it("submits the token with the new password once the entries match", async () => {
    const calls: unknown[] = [];
    const client = stub({
      passwordResetConfirm: (payload: unknown) => {
        calls.push(payload);
        return Promise.resolve(ok);
      },
    });

    const { container } = render(PasswordResetConfirmForm, {
      props: { token: "reset-token" },
      context: withClient(client),
    });

    await type("New password", "new-password-1");
    await type("Confirm new password", "new-password-1");
    await fireEvent.submit(formOf(container));

    await waitFor(() =>
      expect(calls).toEqual([{ token: "reset-token", newPassword: "new-password-1" }]),
    );
    expect((await screen.findByRole("status")).textContent).toBe("Your password has been reset.");
  });

  it("blocks a mismatch in the browser and marks only the confirmation invalid", async () => {
    let called = false;
    const { container } = render(PasswordResetConfirmForm, {
      props: {
        token: "reset-token",
        client: stub({
          passwordResetConfirm: () => {
            called = true;
            return Promise.resolve(ok);
          },
        }),
      },
    });

    await type("New password", "new-password-1");
    await type("Confirm new password", "new-password-2");
    await fireEvent.submit(formOf(container));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("Those passwords do not match.");
    expect(called).toBe(false);
    expect(screen.getByLabelText("Confirm new password").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByLabelText("New password").getAttribute("aria-invalid")).toBeNull();

    // Correcting the confirmation lets the next submit through.
    await type("Confirm new password", "new-password-1");
    await fireEvent.submit(formOf(container));
    await waitFor(() => expect(called).toBe(true));
  });
});

describe("MagicLinkForm", () => {
  it("requests a link and confirms it was sent", async () => {
    const calls: unknown[] = [];
    const client = stub({
      magicLink: {
        send: (payload: unknown) => {
          calls.push(payload);
          return Promise.resolve(ok);
        },
      },
    });

    const { container } = render(MagicLinkForm, { props: {}, context: withClient(client) });

    await type("Email", EMAIL);
    await fireEvent.submit(formOf(container));

    await waitFor(() => expect(calls).toEqual([{ email: EMAIL }]));
    expect((await screen.findByRole("status")).textContent).toBe(
      "Check your inbox for your sign-in link.",
    );
  });

  it('reports a failure through role="alert" and fires onError', async () => {
    const failure = new Error("Magic link is not configured.");
    const seen: unknown[] = [];
    const { container } = render(MagicLinkForm, {
      props: {
        client: stub({ magicLink: { send: () => Promise.reject(failure) } }),
        onError: (cause: unknown) => seen.push(cause),
      },
    });

    await fireEvent.submit(formOf(container));
    expect((await screen.findByRole("alert")).textContent).toBe("Magic link is not configured.");
    expect(seen).toEqual([failure]);
  });
});

describe("EmailOtpForm", () => {
  const otpClient = (calls: unknown[]) =>
    stub({
      emailOtp: {
        send: (payload: unknown) => {
          calls.push(["send", payload]);
          return Promise.resolve(ok);
        },
        signIn: (payload: unknown) => {
          calls.push(["signIn", payload]);
          return Promise.resolve(authSuccess);
        },
      },
    });

  it("sends a code, swaps to the verify step, then signs in", async () => {
    const calls: unknown[] = [];
    const seen: AuthSuccess[] = [];
    const { container } = render(EmailOtpForm, {
      props: { onSuccess: (result: AuthSuccess) => seen.push(result) },
      context: withClient(otpClient(calls)),
    });

    expect(formOf(container).dataset["step"]).toBe("request");
    await type("Email", EMAIL);
    await fireEvent.submit(formOf(container));

    await waitFor(() => expect(calls[0]).toEqual(["send", { email: EMAIL, purpose: "sign-in" }]));
    await waitFor(() => expect(formOf(container).dataset["step"]).toBe("verify"));
    // The request step fires no onSuccess — only the step that yields a session does.
    expect(seen).toEqual([]);

    const code = screen.getByLabelText("Sign-in code");
    expect(code.getAttribute("autocomplete")).toBe("one-time-code");
    expect(code.getAttribute("inputmode")).toBe("numeric");
    await fireEvent.input(code, { target: { value: "123456" } });
    await fireEvent.submit(formOf(container));

    await waitFor(() => expect(calls[1]).toEqual(["signIn", { email: EMAIL, otp: "123456" }]));
    expect(seen).toEqual([authSuccess]);
  });

  it("honours a non-default purpose", async () => {
    const calls: unknown[] = [];
    const { container } = render(EmailOtpForm, {
      props: { client: otpClient(calls), purpose: "email-verification" },
    });

    await type("Email", EMAIL);
    await fireEvent.submit(formOf(container));
    await waitFor(() =>
      expect(calls[0]).toEqual(["send", { email: EMAIL, purpose: "email-verification" }]),
    );
  });

  it("stays on the request step when sending fails", async () => {
    const { container } = render(EmailOtpForm, {
      props: {
        client: stub({ emailOtp: { send: () => Promise.reject(new Error("Too many requests.")) } }),
      },
    });

    await fireEvent.submit(formOf(container));
    expect((await screen.findByRole("alert")).textContent).toBe("Too many requests.");
    expect(formOf(container).dataset["step"]).toBe("request");
  });

  it("returns to the email step, clearing the code", async () => {
    const calls: unknown[] = [];
    const { container } = render(EmailOtpForm, { props: { client: otpClient(calls) } });

    await type("Email", EMAIL);
    await fireEvent.submit(formOf(container));
    await waitFor(() => expect(formOf(container).dataset["step"]).toBe("verify"));

    await fireEvent.input(screen.getByLabelText("Sign-in code"), { target: { value: "123456" } });
    await fireEvent.click(screen.getByRole("button", { name: "Use a different email" }));

    await waitFor(() => expect(formOf(container).dataset["step"]).toBe("request"));
    expect((screen.getByLabelText("Email") as HTMLInputElement).value).toBe(EMAIL);

    await fireEvent.submit(formOf(container));
    await waitFor(() => expect(formOf(container).dataset["step"]).toBe("verify"));
    expect((screen.getByLabelText("Sign-in code") as HTMLInputElement).value).toBe("");
  });

  it("disables the submit button while the code is being sent", async () => {
    const gate = deferred<StatusResponse>();
    const { container } = render(EmailOtpForm, {
      props: { client: stub({ emailOtp: { send: () => gate.promise } }) },
    });

    await fireEvent.submit(formOf(container));
    expect((screen.getByRole("button", { name: "Sending…" }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    gate.resolve(ok);
    await waitFor(() => expect(formOf(container).dataset["step"]).toBe("verify"));
  });
});
