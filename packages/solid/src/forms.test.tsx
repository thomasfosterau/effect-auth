import { describe, expect, it } from "vite-plus/test";
import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import {
  AuthClientProvider,
  EmailOtpForm,
  MagicLinkForm,
  PasswordResetConfirmForm,
  PasswordResetRequestForm,
  SignInForm,
  SignUpForm,
} from "./index.jsx";
import type { AuthSuccess, StatusResponse } from "./index.jsx";

const EMAIL = "alice@solid.test";
const PW = "password-123";

const now = Date.now();
const authSuccess: AuthSuccess = {
  user: { id: "user-1", email: EMAIL, createdAt: now, updatedAt: now, attributes: {} },
  needsEmailVerification: false,
};
const ok: StatusResponse = { status: true };

/**
 * Only the handful of methods a given form touches are stubbed; the components
 * never reach for anything else on the client, and a stand-in object keeps
 * each assertion about one call and one payload.
 */
/** A member as a stub may supply it: a method as is, a namespace as any subset of its members. */
type StubOf<T> = T extends (...args: infer A) => infer R
  ? (...args: A) => R
  : { readonly [K in keyof T]?: StubOf<T[K]> };

/** Any subset of the client's members; the code under test touches only the ones a test supplies. */
type ClientStub = StubOf<AuthClient>;
const stub = (methods: ClientStub): AuthClient => methods as AuthClient;

/** A promise plus the handles to settle it, for driving the pending state. */
const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const type = (label: string, value: string): void => {
  fireEvent.input(screen.getByLabelText(label), { target: { value } });
};

const submit = (container: HTMLElement): void => {
  fireEvent.submit(container.querySelector("form") as HTMLFormElement);
};

const submitButton = (container: HTMLElement): HTMLButtonElement =>
  container.querySelector(".ea-submit") as HTMLButtonElement;

describe("SignInForm", () => {
  it("submits email + password to signIn and fires onSuccess", async () => {
    const calls: Array<unknown> = [];
    const seen: Array<AuthSuccess> = [];
    const { container } = render(() => (
      <SignInForm
        client={stub({
          signIn: (payload: object) => {
            calls.push(payload);
            return Promise.resolve(authSuccess);
          },
        })}
        onSuccess={(result) => seen.push(result)}
      />
    ));

    type("Email", EMAIL);
    type("Password", PW);
    submit(container);

    await waitFor(() => expect(seen).toEqual([authSuccess]));
    expect(calls).toEqual([{ email: EMAIL, password: PW }]);
    expect(container.querySelector(".ea-form")).not.toBeNull();
    expect(container.querySelector(".ea-sign-in")).not.toBeNull();
  });

  it("uses signInUsername for the username variant", async () => {
    const calls: Array<unknown> = [];
    const { container } = render(() => (
      <SignInForm
        client={stub({
          signInUsername: (payload: object) => {
            calls.push(payload);
            return Promise.resolve(authSuccess);
          },
        })}
        variant="username"
      />
    ));

    expect(screen.getByLabelText("Username").getAttribute("autocomplete")).toBe("username");
    type("Username", "alice");
    type("Password", PW);
    submit(container);

    await waitFor(() => expect(calls).toEqual([{ username: "alice", password: PW }]));
  });

  it("renders the failure in an alert and fires onError", async () => {
    const failure = new Error("Bad credentials");
    const seen: Array<unknown> = [];
    const { container } = render(() => (
      <SignInForm
        client={stub({ signIn: () => Promise.reject(failure) })}
        onError={(cause) => seen.push(cause)}
      />
    ));

    submit(container);

    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Bad credentials"));
    expect(seen).toEqual([failure]);
    expect(screen.getByLabelText("Email").getAttribute("aria-invalid")).toBe("true");
  });

  it("disables the submit button while pending", async () => {
    const pending = deferred<AuthSuccess>();
    const { container } = render(() => (
      <SignInForm client={stub({ signIn: () => pending.promise })} />
    ));

    expect(submitButton(container).disabled).toBe(false);
    submit(container);
    expect(submitButton(container).disabled).toBe(true);
    expect(submitButton(container).textContent).toBe("Signing in…");
    expect(container.querySelector("form")?.getAttribute("aria-busy")).toBe("true");

    pending.resolve(authSuccess);
    await waitFor(() => expect(submitButton(container).disabled).toBe(false));
  });

  it("takes its client from the provider, and lets the prop override it", async () => {
    const calls: Array<string> = [];
    const fromContext = stub({
      signIn: () => {
        calls.push("context");
        return Promise.resolve(authSuccess);
      },
    });
    const fromProp = stub({
      signIn: () => {
        calls.push("prop");
        return Promise.resolve(authSuccess);
      },
    });

    const { container } = render(() => (
      <AuthClientProvider client={fromContext}>
        <SignInForm />
        <SignInForm client={fromProp} />
      </AuthClientProvider>
    ));

    const [first, second] = Array.from(container.querySelectorAll("form"));
    fireEvent.submit(first as HTMLFormElement);
    await waitFor(() => expect(calls).toEqual(["context"]));
    fireEvent.submit(second as HTMLFormElement);
    await waitFor(() => expect(calls).toEqual(["context", "prop"]));
  });

  it("honours the class, classes and labels props", () => {
    const { container } = render(() => (
      <SignInForm
        class="my-card"
        classes={{ submit: "btn btn-primary" }}
        client={stub({})}
        labels={{ submit: "Log in" }}
      />
    ));

    const form = container.querySelector("form") as HTMLFormElement;
    expect(form.className).toBe("ea-form ea-sign-in my-card");
    expect(container.querySelector(".btn.btn-primary")?.textContent).toBe("Log in");
    // Unmentioned labels and elements keep their defaults.
    expect(screen.getByLabelText("Email").className).toBe("ea-input");
  });
});

describe("SignUpForm", () => {
  it("submits email, password and a trimmed name to signUp", async () => {
    const calls: Array<unknown> = [];
    const seen: Array<AuthSuccess> = [];
    const { container } = render(() => (
      <SignUpForm
        client={stub({
          signUp: (payload: object) => {
            calls.push(payload);
            return Promise.resolve(authSuccess);
          },
        })}
        onSuccess={(result) => seen.push(result)}
      />
    ));

    type("Name", "  Alice  ");
    type("Email", EMAIL);
    type("Password", PW);
    submit(container);

    await waitFor(() => expect(seen).toEqual([authSuccess]));
    expect(calls).toEqual([{ email: EMAIL, password: PW, name: "Alice" }]);
    expect(screen.getByLabelText("Password").getAttribute("autocomplete")).toBe("new-password");
  });

  it("omits a blank name from the payload and hides the field on request", async () => {
    const calls: Array<unknown> = [];
    const { container } = render(() => (
      <SignUpForm
        client={stub({
          signUp: (payload: object) => {
            calls.push(payload);
            return Promise.resolve(authSuccess);
          },
        })}
        showName={false}
      />
    ));

    expect(screen.queryByLabelText("Name")).toBeNull();
    type("Email", EMAIL);
    type("Password", PW);
    submit(container);

    await waitFor(() => expect(calls).toEqual([{ email: EMAIL, password: PW }]));
  });

  it("renders the failure in an alert and fires onError", async () => {
    const failure = new Error("Email already taken");
    const seen: Array<unknown> = [];
    const { container } = render(() => (
      <SignUpForm
        client={stub({ signUp: () => Promise.reject(failure) })}
        onError={(cause) => seen.push(cause)}
      />
    ));

    submit(container);

    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Email already taken"));
    expect(seen).toEqual([failure]);
  });

  it("disables the submit button while pending", async () => {
    const pending = deferred<AuthSuccess>();
    const { container } = render(() => (
      <SignUpForm client={stub({ signUp: () => pending.promise })} />
    ));

    submit(container);
    expect(submitButton(container).disabled).toBe(true);

    pending.resolve(authSuccess);
    await waitFor(() => expect(submitButton(container).disabled).toBe(false));
  });
});

describe("PasswordResetRequestForm", () => {
  it("submits the email and reports success in a status element", async () => {
    const calls: Array<unknown> = [];
    const seen: Array<StatusResponse> = [];
    const { container } = render(() => (
      <PasswordResetRequestForm
        client={stub({
          passwordResetRequest: (payload: object) => {
            calls.push(payload);
            return Promise.resolve(ok);
          },
        })}
        onSuccess={(result) => seen.push(result)}
      />
    ));

    type("Email", EMAIL);
    submit(container);

    await waitFor(() => expect(seen).toEqual([ok]));
    expect(calls).toEqual([{ email: EMAIL }]);
    expect(screen.getByRole("status").textContent).toContain("reset link");
  });

  it("renders the failure in an alert and fires onError", async () => {
    const failure = new Error("Rate limited");
    const seen: Array<unknown> = [];
    const { container } = render(() => (
      <PasswordResetRequestForm
        client={stub({ passwordResetRequest: () => Promise.reject(failure) })}
        onError={(cause) => seen.push(cause)}
      />
    ));

    submit(container);

    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Rate limited"));
    expect(seen).toEqual([failure]);
  });

  it("disables the submit button while pending", async () => {
    const pending = deferred<StatusResponse>();
    const { container } = render(() => (
      <PasswordResetRequestForm client={stub({ passwordResetRequest: () => pending.promise })} />
    ));

    submit(container);
    expect(submitButton(container).disabled).toBe(true);

    pending.resolve(ok);
    await waitFor(() => expect(submitButton(container).disabled).toBe(false));
  });
});

describe("PasswordResetConfirmForm", () => {
  it("submits the token with the new password", async () => {
    const calls: Array<unknown> = [];
    const seen: Array<StatusResponse> = [];
    const { container } = render(() => (
      <PasswordResetConfirmForm
        client={stub({
          passwordResetConfirm: (payload: object) => {
            calls.push(payload);
            return Promise.resolve(ok);
          },
        })}
        onSuccess={(result) => seen.push(result)}
        token="reset-token"
      />
    ));

    type("New password", PW);
    type("Confirm new password", PW);
    submit(container);

    await waitFor(() => expect(seen).toEqual([ok]));
    expect(calls).toEqual([{ token: "reset-token", newPassword: PW }]);
  });

  it("refuses mismatched passwords without calling the client", async () => {
    let called = false;
    const { container } = render(() => (
      <PasswordResetConfirmForm
        client={stub({
          passwordResetConfirm: () => {
            called = true;
            return Promise.resolve(ok);
          },
        })}
        token="reset-token"
      />
    ));

    type("New password", PW);
    type("Confirm new password", "something-else");
    submit(container);

    expect(screen.getByRole("alert").textContent).toBe("Those passwords do not match.");
    expect(called).toBe(false);
    expect(screen.getByLabelText("Confirm new password").getAttribute("aria-invalid")).toBe("true");
    // The mismatch is attributed to the confirmation field only.
    expect(screen.getByLabelText("New password").getAttribute("aria-invalid")).toBeNull();
  });

  it("renders the failure in an alert and fires onError", async () => {
    const failure = new Error("Token expired");
    const seen: Array<unknown> = [];
    const { container } = render(() => (
      <PasswordResetConfirmForm
        client={stub({ passwordResetConfirm: () => Promise.reject(failure) })}
        onError={(cause) => seen.push(cause)}
        token="reset-token"
      />
    ));

    submit(container);

    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Token expired"));
    expect(seen).toEqual([failure]);
  });

  it("disables the submit button while pending", async () => {
    const pending = deferred<StatusResponse>();
    const { container } = render(() => (
      <PasswordResetConfirmForm
        client={stub({ passwordResetConfirm: () => pending.promise })}
        token="reset-token"
      />
    ));

    submit(container);
    expect(submitButton(container).disabled).toBe(true);

    pending.resolve(ok);
    await waitFor(() => expect(submitButton(container).disabled).toBe(false));
  });
});

describe("MagicLinkForm", () => {
  it("submits the email to magicLink.send", async () => {
    const calls: Array<unknown> = [];
    const seen: Array<StatusResponse> = [];
    const { container } = render(() => (
      <MagicLinkForm
        client={stub({
          magicLink: {
            send: (payload: object) => {
              calls.push(payload);
              return Promise.resolve(ok);
            },
          },
        })}
        onSuccess={(result) => seen.push(result)}
      />
    ));

    type("Email", EMAIL);
    submit(container);

    await waitFor(() => expect(seen).toEqual([ok]));
    expect(calls).toEqual([{ email: EMAIL }]);
    expect(screen.getByRole("status").textContent).toContain("sign-in link");
  });

  it("renders the failure in an alert and fires onError", async () => {
    const failure = new Error("Mailer down");
    const seen: Array<unknown> = [];
    const { container } = render(() => (
      <MagicLinkForm
        client={stub({ magicLink: { send: () => Promise.reject(failure) } })}
        onError={(cause) => seen.push(cause)}
      />
    ));

    submit(container);

    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Mailer down"));
    expect(seen).toEqual([failure]);
  });

  it("disables the submit button while pending", async () => {
    const pending = deferred<StatusResponse>();
    const { container } = render(() => (
      <MagicLinkForm client={stub({ magicLink: { send: () => pending.promise } })} />
    ));

    submit(container);
    expect(submitButton(container).disabled).toBe(true);

    pending.resolve(ok);
    await waitFor(() => expect(submitButton(container).disabled).toBe(false));
  });
});

describe("EmailOtpForm", () => {
  it("requests a code, then verifies it and fires onSuccess", async () => {
    const sends: Array<unknown> = [];
    const verifications: Array<unknown> = [];
    const seen: Array<AuthSuccess> = [];
    const { container } = render(() => (
      <EmailOtpForm
        client={stub({
          emailOtp: {
            send: (payload: object) => {
              sends.push(payload);
              return Promise.resolve(ok);
            },
            signIn: (payload: object) => {
              verifications.push(payload);
              return Promise.resolve(authSuccess);
            },
          },
        })}
        onSuccess={(result) => seen.push(result)}
      />
    ));

    expect(container.querySelector("form")?.getAttribute("data-step")).toBe("request");
    type("Email", EMAIL);
    submit(container);

    await waitFor(() => expect(screen.getByLabelText("Sign-in code")).toBeDefined());
    expect(sends).toEqual([{ email: EMAIL, purpose: "sign-in" }]);
    expect(container.querySelector("form")?.getAttribute("data-step")).toBe("verify");
    expect(screen.getByLabelText("Sign-in code").getAttribute("autocomplete")).toBe(
      "one-time-code",
    );
    // The request step succeeding is not an authentication.
    expect(seen).toEqual([]);

    type("Sign-in code", "123456");
    submit(container);

    await waitFor(() => expect(seen).toEqual([authSuccess]));
    expect(verifications).toEqual([{ email: EMAIL, otp: "123456" }]);
  });

  it("renders a failed request in an alert and fires onError", async () => {
    const failure = new Error("Unknown address");
    const seen: Array<unknown> = [];
    const { container } = render(() => (
      <EmailOtpForm
        client={stub({ emailOtp: { send: () => Promise.reject(failure) } })}
        onError={(cause) => seen.push(cause)}
      />
    ));

    submit(container);

    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Unknown address"));
    expect(seen).toEqual([failure]);
    expect(container.querySelector("form")?.getAttribute("data-step")).toBe("request");
  });

  it("disables the submit button while pending", async () => {
    const pending = deferred<StatusResponse>();
    const { container } = render(() => (
      <EmailOtpForm client={stub({ emailOtp: { send: () => pending.promise } })} />
    ));

    submit(container);
    expect(submitButton(container).disabled).toBe(true);
    expect(submitButton(container).textContent).toBe("Sending…");

    pending.resolve(ok);
    await waitFor(() => expect(screen.getByLabelText("Sign-in code")).toBeDefined());
  });
});
