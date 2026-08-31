// @vitest-environment jsdom
import { describe, it, expect } from "vite-plus/test";
import {
  act,
  cleanup,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { AuthClientError } from "@thomasfosterau/effect-auth-client";
import {
  AuthClientProvider,
  EmailOtpForm,
  MagicLinkForm,
  PasswordResetConfirmForm,
  PasswordResetRequestForm,
  SignInForm,
  SignUpForm,
  useAuthClient,
} from "./index.ts";

/**
 * The forms only ever touch a handful of client methods, so the tests stand a
 * plain object in for the client rather than a `fetch` stub: the assertion that
 * matters is "this method, with this payload", which a recorded call states
 * directly.
 */
const stub = (methods: Record<string, unknown>): AuthClient => methods as unknown as AuthClient;

/** A recording stand-in for one client method. */
const spy = <T,>(result: () => Promise<T>) => {
  const calls: unknown[] = [];
  const fn = (payload?: unknown): Promise<T> => {
    calls.push(payload);
    return result();
  };
  return Object.assign(fn, { calls });
};

const resolving = <T,>(value: T) => spy(() => Promise.resolve(value));
const rejecting = (error: unknown) => spy(() => Promise.reject(error));

/** A promise whose settlement the test controls, for asserting pending state. */
const deferred = <T,>() => {
  let settle!: (value: T) => void;
  const promise = new Promise<T>((resolve) => {
    settle = resolve;
  });
  return { promise, settle };
};

const SUCCESS = { user: { id: "u1" }, needsEmailVerification: false };
const STATUS = { status: "ok" };

/** Submit the rendered form directly, bypassing browser constraint validation. */
const submit = (container: HTMLElement): void => {
  const form = container.querySelector("form");
  if (form === null) throw new Error("no <form> rendered");
  fireEvent.submit(form);
};

const form = (container: HTMLElement): HTMLFormElement => {
  const found = container.querySelector("form");
  if (found === null) throw new Error("no <form> rendered");
  return found;
};

const fill = (label: string | RegExp, value: string): void => {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
};

const input = (label: string | RegExp): HTMLInputElement =>
  screen.getByLabelText(label) as HTMLInputElement;

describe("AuthClientProvider / useAuthClient", () => {
  it("throws a directive error when used outside a provider", () => {
    expect(() => renderHook(() => useAuthClient())).toThrow(/AuthClientProvider/);
    cleanup();
  });

  it("hands descendants the provided client", () => {
    const client = stub({});
    const { result } = renderHook(() => useAuthClient(), {
      wrapper: ({ children }) => (
        <AuthClientProvider client={client}>{children}</AuthClientProvider>
      ),
    });
    expect(result.current).toBe(client);
    cleanup();
  });

  it("lets a `client` prop override the one in context", async () => {
    const fromContext = resolving(SUCCESS);
    const fromProp = resolving(SUCCESS);
    const { container } = render(
      <AuthClientProvider client={stub({ signIn: fromContext })}>
        <SignInForm client={stub({ signIn: fromProp })} />
      </AuthClientProvider>,
    );

    fill("Email", "a@b.test");
    fill("Password", "pw");
    submit(container);

    await waitFor(() => expect(fromProp.calls.length).toBe(1));
    expect(fromContext.calls.length).toBe(0);
    cleanup();
  });

  it("throws from a form rendered with neither provider nor client prop", () => {
    expect(() => render(<SignInForm />)).toThrow(/AuthClientProvider/);
    cleanup();
  });
});

describe("SignInForm", () => {
  it("renders email + password fields with the default labels", () => {
    const { container } = render(<SignInForm client={stub({})} />);

    expect(form(container).className).toBe("ea-form ea-sign-in");
    expect(input("Email").type).toBe("email");
    expect(input("Email").getAttribute("autocomplete")).toBe("email");
    expect(input("Password").type).toBe("password");
    expect(input("Password").getAttribute("autocomplete")).toBe("current-password");
    expect(screen.getByRole("button", { name: "Sign in" })).toBeDefined();
    expect(screen.queryByRole("alert")).toBeNull();
    cleanup();
  });

  it("signs in with the typed email payload and fires onSuccess", async () => {
    const signIn = resolving(SUCCESS);
    const seen: unknown[] = [];
    const { container } = render(
      <SignInForm client={stub({ signIn })} onSuccess={(result) => seen.push(result)} />,
    );

    fill("Email", "alice@example.test");
    fill("Password", "correct horse");
    submit(container);

    await waitFor(() => expect(seen).toEqual([SUCCESS]));
    expect(signIn.calls).toEqual([{ email: "alice@example.test", password: "correct horse" }]);
    cleanup();
  });

  it("submits when the submit button is clicked", async () => {
    const signIn = resolving(SUCCESS);
    render(<SignInForm client={stub({ signIn })} />);

    fill("Email", "alice@example.test");
    fill("Password", "pw");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(signIn.calls.length).toBe(1));
    cleanup();
  });

  it('calls signInUsername for variant="username"', async () => {
    const signInUsername = resolving(SUCCESS);
    const { container } = render(
      <SignInForm client={stub({ signInUsername })} variant="username" />,
    );

    expect(input("Username").type).toBe("text");
    expect(input("Username").getAttribute("autocomplete")).toBe("username");

    fill("Username", "alice");
    fill("Password", "pw");
    submit(container);

    await waitFor(() =>
      expect(signInUsername.calls).toEqual([{ username: "alice", password: "pw" }]),
    );
    cleanup();
  });

  it('renders the server message in role="alert", marks fields invalid and fires onError', async () => {
    const cause = new AuthClientError(401, "Invalid email or password.");
    const seen: unknown[] = [];
    const { container } = render(
      <SignInForm client={stub({ signIn: rejecting(cause) })} onError={(e) => seen.push(e)} />,
    );

    fill("Email", "alice@example.test");
    fill("Password", "wrong");
    submit(container);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("Invalid email or password.");
    expect(alert.className).toBe("ea-error");
    expect(input("Email").getAttribute("aria-invalid")).toBe("true");
    expect(input("Password").getAttribute("aria-invalid")).toBe("true");
    expect(seen).toEqual([cause]);
    cleanup();
  });

  it("falls back to the overridable generic message when the error carries none", async () => {
    const { container } = render(
      <SignInForm
        client={stub({ signIn: rejecting(new Error("")) })}
        labels={{ error: "Nope." }}
      />,
    );

    fill("Email", "a@b.test");
    fill("Password", "pw");
    submit(container);

    expect((await screen.findByRole("alert")).textContent).toBe("Nope.");
    cleanup();
  });

  it("disables the submit button and marks the form busy while pending", async () => {
    const gate = deferred<typeof SUCCESS>();
    const { container } = render(<SignInForm client={stub({ signIn: () => gate.promise })} />);

    fill("Email", "a@b.test");
    fill("Password", "pw");
    submit(container);

    const button = screen.getByRole("button", { name: "Signing in…" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(form(container).getAttribute("aria-busy")).toBe("true");
    expect(input("Email").disabled).toBe(true);

    await act(async () => {
      gate.settle(SUCCESS);
    });

    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Sign in" }) as HTMLButtonElement).disabled).toBe(
        false,
      ),
    );
    expect(form(container).getAttribute("aria-busy")).toBeNull();
    cleanup();
  });

  it("honours className, classes and labels overrides", () => {
    const { container } = render(
      <SignInForm
        classes={{ input: "field-control", submit: "btn btn-primary" }}
        className="max-w-sm"
        client={stub({})}
        labels={{ email: "Work email", submit: "Continue" }}
      />,
    );

    expect(form(container).className).toBe("ea-form ea-sign-in max-w-sm");
    expect(input("Work email").className).toBe("field-control");
    expect(screen.getByRole("button", { name: "Continue" }).className).toBe("btn btn-primary");
    cleanup();
  });
});

describe("SignUpForm", () => {
  it("renders name, email and password by default", () => {
    const { container } = render(<SignUpForm client={stub({})} />);

    expect(form(container).className).toBe("ea-form ea-sign-up");
    expect(input("Name").required).toBe(false);
    expect(input("Email").getAttribute("autocomplete")).toBe("email");
    expect(input("Password").getAttribute("autocomplete")).toBe("new-password");
    expect(screen.getByRole("button", { name: "Create account" })).toBeDefined();
    cleanup();
  });

  it("signs up with name included and fires onSuccess", async () => {
    const signUp = resolving(SUCCESS);
    const seen: unknown[] = [];
    const { container } = render(
      <SignUpForm client={stub({ signUp })} onSuccess={(result) => seen.push(result)} />,
    );

    fill("Name", "  Alice  ");
    fill("Email", "alice@example.test");
    fill("Password", "hunter2hunter2");
    submit(container);

    await waitFor(() => expect(seen).toEqual([SUCCESS]));
    expect(signUp.calls).toEqual([
      { email: "alice@example.test", password: "hunter2hunter2", name: "Alice" },
    ]);
    cleanup();
  });

  it("omits an absent name, and the field entirely when showName is false", async () => {
    const signUp = resolving(SUCCESS);
    const { container } = render(<SignUpForm client={stub({ signUp })} showName={false} />);

    expect(screen.queryByLabelText("Name")).toBeNull();

    fill("Email", "alice@example.test");
    fill("Password", "hunter2hunter2");
    submit(container);

    await waitFor(() =>
      expect(signUp.calls).toEqual([{ email: "alice@example.test", password: "hunter2hunter2" }]),
    );
    cleanup();
  });

  it("renders the failure and fires onError", async () => {
    const cause = new AuthClientError(409, "That email is already registered.");
    const seen: unknown[] = [];
    const { container } = render(
      <SignUpForm client={stub({ signUp: rejecting(cause) })} onError={(e) => seen.push(e)} />,
    );

    fill("Email", "alice@example.test");
    fill("Password", "pw");
    submit(container);

    expect((await screen.findByRole("alert")).textContent).toBe(
      "That email is already registered.",
    );
    expect(seen).toEqual([cause]);
    cleanup();
  });

  it("disables the submit button while pending", async () => {
    const gate = deferred<typeof SUCCESS>();
    const { container } = render(<SignUpForm client={stub({ signUp: () => gate.promise })} />);

    fill("Email", "a@b.test");
    fill("Password", "pw");
    submit(container);

    expect(
      (screen.getByRole("button", { name: "Creating account…" }) as HTMLButtonElement).disabled,
    ).toBe(true);

    await act(async () => {
      gate.settle(SUCCESS);
    });
    cleanup();
  });
});

describe("PasswordResetRequestForm", () => {
  it("renders a single email field", () => {
    const { container } = render(<PasswordResetRequestForm client={stub({})} />);

    expect(form(container).className).toBe("ea-form ea-password-reset-request");
    expect(input("Email").type).toBe("email");
    expect(screen.getByRole("button", { name: "Send reset link" })).toBeDefined();
    cleanup();
  });

  it("requests the reset, fires onSuccess and shows the status message", async () => {
    const passwordResetRequest = resolving(STATUS);
    const seen: unknown[] = [];
    const { container } = render(
      <PasswordResetRequestForm
        client={stub({ passwordResetRequest })}
        onSuccess={(result) => seen.push(result)}
      />,
    );

    fill("Email", "alice@example.test");
    submit(container);

    await waitFor(() => expect(seen).toEqual([STATUS]));
    expect(passwordResetRequest.calls).toEqual([{ email: "alice@example.test" }]);
    expect((await screen.findByRole("status")).textContent).toMatch(/reset link is on its way/);
    cleanup();
  });

  it("renders the failure and fires onError", async () => {
    const cause = new AuthClientError(429, "Too many requests.");
    const seen: unknown[] = [];
    const { container } = render(
      <PasswordResetRequestForm
        client={stub({ passwordResetRequest: rejecting(cause) })}
        onError={(e) => seen.push(e)}
      />,
    );

    fill("Email", "alice@example.test");
    submit(container);

    expect((await screen.findByRole("alert")).textContent).toBe("Too many requests.");
    expect(input("Email").getAttribute("aria-invalid")).toBe("true");
    expect(seen).toEqual([cause]);
    cleanup();
  });

  it("disables the submit button while pending", async () => {
    const gate = deferred<typeof STATUS>();
    const { container } = render(
      <PasswordResetRequestForm client={stub({ passwordResetRequest: () => gate.promise })} />,
    );

    fill("Email", "a@b.test");
    submit(container);
    expect((screen.getByRole("button", { name: "Sending…" }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    await act(async () => {
      gate.settle(STATUS);
    });
    cleanup();
  });
});

describe("PasswordResetConfirmForm", () => {
  it("renders two new-password fields", () => {
    const { container } = render(<PasswordResetConfirmForm client={stub({})} token="t" />);

    expect(form(container).className).toBe("ea-form ea-password-reset-confirm");
    expect(input("New password").getAttribute("autocomplete")).toBe("new-password");
    expect(input("Confirm new password").getAttribute("autocomplete")).toBe("new-password");
    cleanup();
  });

  it("confirms with the token and the new password, and fires onSuccess", async () => {
    const passwordResetConfirm = resolving(STATUS);
    const seen: unknown[] = [];
    const { container } = render(
      <PasswordResetConfirmForm
        client={stub({ passwordResetConfirm })}
        onSuccess={(result) => seen.push(result)}
        token="reset-token-1"
      />,
    );

    fill("New password", "brand-new-pw");
    fill("Confirm new password", "brand-new-pw");
    submit(container);

    await waitFor(() => expect(seen).toEqual([STATUS]));
    expect(passwordResetConfirm.calls).toEqual([
      { token: "reset-token-1", newPassword: "brand-new-pw" },
    ]);
    cleanup();
  });

  it("rejects a mismatch client-side, marking only the confirmation invalid", () => {
    const passwordResetConfirm = resolving(STATUS);
    const { container } = render(
      <PasswordResetConfirmForm client={stub({ passwordResetConfirm })} token="t" />,
    );

    fill("New password", "brand-new-pw");
    fill("Confirm new password", "brand-new-pw-typo");
    submit(container);

    expect(screen.getByRole("alert").textContent).toBe("Those passwords do not match.");
    expect(input("Confirm new password").getAttribute("aria-invalid")).toBe("true");
    expect(input("New password").getAttribute("aria-invalid")).toBeNull();
    expect(passwordResetConfirm.calls.length).toBe(0);
    cleanup();
  });

  it("renders the failure and fires onError", async () => {
    const cause = new AuthClientError(400, "That reset link has expired.");
    const seen: unknown[] = [];
    const { container } = render(
      <PasswordResetConfirmForm
        client={stub({ passwordResetConfirm: rejecting(cause) })}
        onError={(e) => seen.push(e)}
        token="t"
      />,
    );

    fill("New password", "pw");
    fill("Confirm new password", "pw");
    submit(container);

    expect((await screen.findByRole("alert")).textContent).toBe("That reset link has expired.");
    expect(seen).toEqual([cause]);
    cleanup();
  });

  it("disables the submit button while pending", async () => {
    const gate = deferred<typeof STATUS>();
    const { container } = render(
      <PasswordResetConfirmForm
        client={stub({ passwordResetConfirm: () => gate.promise })}
        token="t"
      />,
    );

    fill("New password", "pw");
    fill("Confirm new password", "pw");
    submit(container);
    expect((screen.getByRole("button", { name: "Resetting…" }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    await act(async () => {
      gate.settle(STATUS);
    });
    cleanup();
  });
});

describe("MagicLinkForm", () => {
  it("renders a single email field", () => {
    const { container } = render(<MagicLinkForm client={stub({})} />);

    expect(form(container).className).toBe("ea-form ea-magic-link");
    expect(input("Email").getAttribute("autocomplete")).toBe("email");
    expect(screen.getByRole("button", { name: "Email me a sign-in link" })).toBeDefined();
    cleanup();
  });

  it("sends the link via magicLink.send and fires onSuccess", async () => {
    const send = resolving(STATUS);
    const seen: unknown[] = [];
    const { container } = render(
      <MagicLinkForm
        client={stub({ magicLink: { send } })}
        onSuccess={(result) => seen.push(result)}
      />,
    );

    fill("Email", "alice@example.test");
    submit(container);

    await waitFor(() => expect(seen).toEqual([STATUS]));
    expect(send.calls).toEqual([{ email: "alice@example.test" }]);
    expect((await screen.findByRole("status")).textContent).toMatch(/sign-in link/);
    cleanup();
  });

  it("renders the failure and fires onError", async () => {
    const cause = new AuthClientError(404, "Magic links are not enabled.");
    const seen: unknown[] = [];
    const { container } = render(
      <MagicLinkForm
        client={stub({ magicLink: { send: rejecting(cause) } })}
        onError={(e) => seen.push(e)}
      />,
    );

    fill("Email", "alice@example.test");
    submit(container);

    expect((await screen.findByRole("alert")).textContent).toBe("Magic links are not enabled.");
    expect(seen).toEqual([cause]);
    cleanup();
  });

  it("disables the submit button while pending", async () => {
    const gate = deferred<typeof STATUS>();
    const { container } = render(
      <MagicLinkForm client={stub({ magicLink: { send: () => gate.promise } })} />,
    );

    fill("Email", "a@b.test");
    submit(container);
    expect((screen.getByRole("button", { name: "Sending…" }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    await act(async () => {
      gate.settle(STATUS);
    });
    cleanup();
  });
});

describe("EmailOtpForm", () => {
  it("starts on the request step", () => {
    const { container } = render(<EmailOtpForm client={stub({})} />);

    expect(form(container).className).toBe("ea-form ea-email-otp");
    expect(form(container).getAttribute("data-step")).toBe("request");
    expect(input("Email").type).toBe("email");
    expect(screen.queryByLabelText("Sign-in code")).toBeNull();
    expect(screen.getByRole("button", { name: "Email me a code" })).toBeDefined();
    cleanup();
  });

  it("sends a sign-in code, then verifies it and fires onSuccess", async () => {
    const send = resolving(STATUS);
    const signIn = resolving(SUCCESS);
    const seen: unknown[] = [];
    const { container } = render(
      <EmailOtpForm
        client={stub({ emailOtp: { send, signIn } })}
        onSuccess={(result) => seen.push(result)}
      />,
    );

    fill("Email", "alice@example.test");
    submit(container);

    const code = await screen.findByLabelText("Sign-in code");
    expect(send.calls).toEqual([{ email: "alice@example.test", purpose: "sign-in" }]);
    expect(code.getAttribute("autocomplete")).toBe("one-time-code");
    expect(code.getAttribute("inputmode")).toBe("numeric");
    expect(form(container).getAttribute("data-step")).toBe("verify");
    // Sending the code is not a sign-in, so onSuccess has not fired yet.
    expect(seen).toEqual([]);

    fireEvent.change(code, { target: { value: "123456" } });
    submit(container);

    await waitFor(() => expect(seen).toEqual([SUCCESS]));
    expect(signIn.calls).toEqual([{ email: "alice@example.test", otp: "123456" }]);
    cleanup();
  });

  it("renders a send failure and fires onError without advancing", async () => {
    const cause = new AuthClientError(404, "Email codes are not enabled.");
    const seen: unknown[] = [];
    const { container } = render(
      <EmailOtpForm
        client={stub({ emailOtp: { send: rejecting(cause) } })}
        onError={(e) => seen.push(e)}
      />,
    );

    fill("Email", "alice@example.test");
    submit(container);

    expect((await screen.findByRole("alert")).textContent).toBe("Email codes are not enabled.");
    expect(form(container).getAttribute("data-step")).toBe("request");
    expect(seen).toEqual([cause]);
    cleanup();
  });

  it("renders a verify failure and fires onError", async () => {
    const cause = new AuthClientError(400, "That code is wrong or expired.");
    const seen: unknown[] = [];
    const { container } = render(
      <EmailOtpForm
        client={stub({
          emailOtp: { send: resolving(STATUS), signIn: rejecting(cause) },
        })}
        onError={(e) => seen.push(e)}
      />,
    );

    fill("Email", "alice@example.test");
    submit(container);
    const code = await screen.findByLabelText("Sign-in code");
    fireEvent.change(code, { target: { value: "000000" } });
    submit(container);

    expect((await screen.findByRole("alert")).textContent).toBe("That code is wrong or expired.");
    expect(code.getAttribute("aria-invalid")).toBe("true");
    expect(seen).toEqual([cause]);
    cleanup();
  });

  it("disables the submit button on both steps while pending", async () => {
    const sendGate = deferred<typeof STATUS>();
    const verifyGate = deferred<typeof SUCCESS>();
    const { container } = render(
      <EmailOtpForm
        client={stub({
          emailOtp: { send: () => sendGate.promise, signIn: () => verifyGate.promise },
        })}
      />,
    );

    fill("Email", "a@b.test");
    submit(container);
    expect((screen.getByRole("button", { name: "Sending…" }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    await act(async () => {
      sendGate.settle(STATUS);
    });

    const code = await screen.findByLabelText("Sign-in code");
    fireEvent.change(code, { target: { value: "123456" } });
    submit(container);
    expect((screen.getByRole("button", { name: "Verifying…" }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    await act(async () => {
      verifyGate.settle(SUCCESS);
    });
    cleanup();
  });

  it("returns to the request step from the verify step", async () => {
    const { container } = render(
      <EmailOtpForm client={stub({ emailOtp: { send: resolving(STATUS) } })} />,
    );

    fill("Email", "alice@example.test");
    submit(container);
    await screen.findByLabelText("Sign-in code");

    fireEvent.click(screen.getByRole("button", { name: "Use a different email" }));

    expect(form(container).getAttribute("data-step")).toBe("request");
    expect(input("Email").value).toBe("alice@example.test");
    cleanup();
  });
});
