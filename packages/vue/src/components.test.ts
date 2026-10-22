// @vitest-environment jsdom
import { describe, it, expect, vi } from "vite-plus/test";
import { defineComponent, h, type Component } from "vue";
import { mount, type VueWrapper } from "@vue/test-utils";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";
import { authClientKey, provideAuthClient } from "./context.ts";
import type { AuthSuccess, StatusResponse } from "./forms.ts";
import {
  EmailOtpForm,
  MagicLinkForm,
  PasswordResetConfirmForm,
  PasswordResetRequestForm,
  SignInForm,
  SignUpForm,
} from "./components.ts";

/** A stand-in client exposing only the branch the component under test calls. */
/** A member as a stub may supply it: a method as is, a namespace as any subset of its members. */
type StubOf<T> = T extends (...args: infer A) => infer R
  ? (...args: A) => R
  : { readonly [K in keyof T]?: StubOf<T[K]> };

/** Any subset of the client's members; the code under test touches only the ones a test supplies. */
type ClientStub = StubOf<AuthClient>;
const stub = <T extends ClientStub>(shape: T): T & AuthClient => shape as T & AuthClient;

const AUTH_SUCCESS: AuthSuccess = {
  user: { id: "user-1", email: "alice@vue.test", createdAt: 0, updatedAt: 0, attributes: {} },
  needsEmailVerification: false,
};

const STATUS: StatusResponse = { status: true };

/** The prop values these tests pass: flags, strings, a client, label maps. */
type PropValue = string | boolean | AuthClient | Readonly<Record<string, string>>;

/** Mount with the client handed down through `provide`, as an app would. */
const withClient = (
  component: Component,
  client: AuthClient,
  props: Readonly<Record<string, PropValue>> = {},
) =>
  mount(component, {
    props,
    global: { provide: { [authClientKey as symbol]: client } },
  });

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
};

/** Let the client's promise settle and Vue flush the resulting re-render. */
const settle = async (wrapper: VueWrapper): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await wrapper.vm.$nextTick();
};

const fill = async (wrapper: VueWrapper, name: string, value: string): Promise<void> => {
  await wrapper.get(`input[name="${name}"]`).setValue(value);
};

const submit = async (wrapper: VueWrapper): Promise<void> => {
  await wrapper.get("form").trigger("submit");
  await settle(wrapper);
};

const button = (wrapper: VueWrapper) => wrapper.get("button[type='submit']");

const emitted = (wrapper: VueWrapper, event: string): unknown[][] =>
  (wrapper.emitted(event) ?? []) as unknown[][];

describe("client resolution", () => {
  it("throws a message naming every way to supply a client", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() => mount(SignInForm)).toThrow(/No auth client was provided/);

    warn.mockRestore();
    error.mockRestore();
  });

  it("prefers the client prop over the injected one", async () => {
    const injected = stub({ signIn: vi.fn(() => Promise.resolve(AUTH_SUCCESS)) });
    const override = stub({ signIn: vi.fn(() => Promise.resolve(AUTH_SUCCESS)) });
    const wrapper = withClient(SignInForm, injected, { client: override });

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await submit(wrapper);

    expect(override.signIn).toHaveBeenCalledOnce();
    expect(injected.signIn).not.toHaveBeenCalled();
    expect(emitted(wrapper, "success")).toEqual([[AUTH_SUCCESS]]);
  });

  it("resolves a client an ancestor supplied with provideAuthClient", async () => {
    const client = stub({ magicLink: { send: vi.fn(() => Promise.resolve(STATUS)) } });
    const Parent = defineComponent({
      setup() {
        provideAuthClient(client);
        return () => h(MagicLinkForm);
      },
    });
    const wrapper = mount(Parent);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(client.magicLink.send).toHaveBeenCalledWith({ email: "alice@vue.test" });
  });
});

describe("SignInForm", () => {
  it("renders an accessible email + password form", () => {
    const wrapper = withClient(SignInForm, stub({}));
    const form = wrapper.get("form");

    expect(form.classes()).toEqual(["ea-form", "ea-sign-in"]);
    expect(form.attributes("aria-busy")).toBe("false");

    const email = wrapper.get("input[name='email']");
    expect(email.attributes("type")).toBe("email");
    expect(email.attributes("autocomplete")).toBe("email");
    expect(email.attributes("aria-invalid")).toBeUndefined();
    const password = wrapper.get("input[name='password']");
    expect(password.attributes("autocomplete")).toBe("current-password");

    const labels = wrapper.findAll("label");
    expect(labels.map((label) => label.text())).toEqual(["Email", "Password"]);
    expect(labels.map((label) => label.attributes("for"))).toEqual([
      email.attributes("id"),
      password.attributes("id"),
    ]);
    expect(labels.every((label) => (label.attributes("for") ?? "") !== "")).toBe(true);

    expect(wrapper.find(".ea-field").exists()).toBe(true);
    expect(button(wrapper).text()).toBe("Sign in");
    expect(wrapper.find("[role='alert']").exists()).toBe(false);
  });

  it("calls signIn and emits success", async () => {
    const client = stub({ signIn: vi.fn(() => Promise.resolve(AUTH_SUCCESS)) });
    const wrapper = withClient(SignInForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await submit(wrapper);

    expect(client.signIn).toHaveBeenCalledWith({ email: "alice@vue.test", password: "pw" });
    expect(emitted(wrapper, "success")).toEqual([[AUTH_SUCCESS]]);
    expect(emitted(wrapper, "error")).toEqual([]);
  });

  it("switches to username + password for variant='username'", async () => {
    const client = stub({ signInUsername: vi.fn(() => Promise.resolve(AUTH_SUCCESS)) });
    const wrapper = withClient(SignInForm, client, { variant: "username" });

    expect(wrapper.get("input[name='username']").attributes("autocomplete")).toBe("username");
    expect(wrapper.find("input[name='email']").exists()).toBe(false);
    expect(wrapper.findAll("label")[0]?.text()).toBe("Username");

    await fill(wrapper, "username", "alice");
    await fill(wrapper, "password", "pw");
    await submit(wrapper);

    expect(client.signInUsername).toHaveBeenCalledWith({ username: "alice", password: "pw" });
    expect(emitted(wrapper, "success")).toEqual([[AUTH_SUCCESS]]);
  });

  it("renders the server message in role='alert' and emits error", async () => {
    const cause = new Error("Invalid credentials");
    const client = stub({ signIn: vi.fn(() => Promise.reject(cause)) });
    const wrapper = withClient(SignInForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "wrong");
    await submit(wrapper);

    const message = wrapper.get("[role='alert']");
    expect(message.text()).toBe("Invalid credentials");
    expect(message.classes()).toEqual(["ea-error"]);
    expect(wrapper.get("input[name='email']").attributes("aria-invalid")).toBe("true");
    expect(wrapper.get("input[name='password']").attributes("aria-invalid")).toBe("true");
    expect(emitted(wrapper, "error")).toEqual([[cause]]);
    expect(emitted(wrapper, "success")).toEqual([]);
  });

  it("falls back to the error label when the cause carries no message", async () => {
    const client = stub({ signIn: vi.fn(() => Promise.reject(new Error(""))) });
    const wrapper = withClient(SignInForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await submit(wrapper);

    expect(wrapper.get("[role='alert']").text()).toMatch(/Sign-in failed/);
  });

  it("disables submit and marks the form busy while pending", async () => {
    const pending = deferred<AuthSuccess>();
    const client = stub({ signIn: vi.fn(() => pending.promise) });
    const wrapper = withClient(SignInForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await wrapper.get("form").trigger("submit");

    expect(button(wrapper).attributes("disabled")).toBeDefined();
    expect(button(wrapper).text()).toBe("Signing in…");
    expect(wrapper.get("form").attributes("aria-busy")).toBe("true");

    // A second submit while pending must not fire a second request.
    await wrapper.get("form").trigger("submit");
    expect(client.signIn).toHaveBeenCalledOnce();

    pending.resolve(AUTH_SUCCESS);
    await settle(wrapper);

    expect(button(wrapper).attributes("disabled")).toBeUndefined();
    expect(wrapper.get("form").attributes("aria-busy")).toBe("false");
  });

  it("takes label and class overrides and passes a root class through", () => {
    const wrapper = withClient(SignInForm, stub({}), {
      class: "tenant-theme",
      labels: { email: "Courriel", submit: "Se connecter" },
      classes: { form: "card", input: "field-input" },
    });

    expect(wrapper.get("form").classes().sort()).toEqual(["card", "tenant-theme"]);
    expect(wrapper.findAll("label")[0]?.text()).toBe("Courriel");
    expect(button(wrapper).text()).toBe("Se connecter");
    expect(wrapper.get("input[name='email']").classes()).toEqual(["field-input"]);
    expect(wrapper.find(".ea-field").exists()).toBe(true);
  });
});

describe("SignUpForm", () => {
  it("renders email + password and hides the name field by default", () => {
    const wrapper = withClient(SignUpForm, stub({}));

    expect(wrapper.get("form").classes()).toEqual(["ea-form", "ea-sign-up"]);
    expect(wrapper.find("input[name='name']").exists()).toBe(false);
    expect(wrapper.get("input[name='password']").attributes("autocomplete")).toBe("new-password");
    expect(button(wrapper).text()).toBe("Create account");
  });

  it("calls signUp and emits success", async () => {
    const client = stub({ signUp: vi.fn(() => Promise.resolve(AUTH_SUCCESS)) });
    const wrapper = withClient(SignUpForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await submit(wrapper);

    expect(client.signUp).toHaveBeenCalledWith({ email: "alice@vue.test", password: "pw" });
    expect(emitted(wrapper, "success")).toEqual([[AUTH_SUCCESS]]);
  });

  it("sends the name only when showName is set and the field is filled", async () => {
    const client = stub({ signUp: vi.fn(() => Promise.resolve(AUTH_SUCCESS)) });
    const wrapper = withClient(SignUpForm, client, { showName: true });

    const name = wrapper.get("input[name='name']");
    expect(name.attributes("autocomplete")).toBe("name");
    expect(name.attributes("required")).toBeUndefined();

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await submit(wrapper);
    expect(client.signUp).toHaveBeenLastCalledWith({ email: "alice@vue.test", password: "pw" });

    await fill(wrapper, "name", "  Alice  ");
    await submit(wrapper);
    expect(client.signUp).toHaveBeenLastCalledWith({
      email: "alice@vue.test",
      password: "pw",
      name: "Alice",
    });
  });

  it("renders the failure in role='alert' and emits error", async () => {
    const cause = new Error("Email already registered");
    const client = stub({ signUp: vi.fn(() => Promise.reject(cause)) });
    const wrapper = withClient(SignUpForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await submit(wrapper);

    expect(wrapper.get("[role='alert']").text()).toBe("Email already registered");
    expect(wrapper.get("input[name='email']").attributes("aria-invalid")).toBe("true");
    expect(emitted(wrapper, "error")).toEqual([[cause]]);
  });

  it("disables submit while pending", async () => {
    const pending = deferred<AuthSuccess>();
    const client = stub({ signUp: vi.fn(() => pending.promise) });
    const wrapper = withClient(SignUpForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await fill(wrapper, "password", "pw");
    await wrapper.get("form").trigger("submit");

    expect(button(wrapper).attributes("disabled")).toBeDefined();
    expect(button(wrapper).text()).toBe("Creating account…");
    expect(wrapper.get("form").attributes("aria-busy")).toBe("true");

    pending.resolve(AUTH_SUCCESS);
    await settle(wrapper);
    expect(button(wrapper).attributes("disabled")).toBeUndefined();
  });
});

describe("PasswordResetRequestForm", () => {
  it("renders a single email field", () => {
    const wrapper = withClient(PasswordResetRequestForm, stub({}));

    expect(wrapper.get("form").classes()).toEqual(["ea-form", "ea-password-reset-request"]);
    expect(wrapper.findAll("input")).toHaveLength(1);
    expect(wrapper.get("input[name='email']").attributes("autocomplete")).toBe("email");
    expect(button(wrapper).text()).toBe("Send reset link");
  });

  it("calls passwordResetRequest and emits success", async () => {
    const client = stub({ passwordResetRequest: vi.fn(() => Promise.resolve(STATUS)) });
    const wrapper = withClient(PasswordResetRequestForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(client.passwordResetRequest).toHaveBeenCalledWith({ email: "alice@vue.test" });
    expect(emitted(wrapper, "success")).toEqual([[STATUS]]);
  });

  it("renders the failure in role='alert' and emits error", async () => {
    const cause = new Error("Too many requests");
    const client = stub({ passwordResetRequest: vi.fn(() => Promise.reject(cause)) });
    const wrapper = withClient(PasswordResetRequestForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(wrapper.get("[role='alert']").text()).toBe("Too many requests");
    expect(wrapper.get("input[name='email']").attributes("aria-invalid")).toBe("true");
    expect(emitted(wrapper, "error")).toEqual([[cause]]);
  });

  it("disables submit while pending", async () => {
    const pending = deferred<StatusResponse>();
    const client = stub({ passwordResetRequest: vi.fn(() => pending.promise) });
    const wrapper = withClient(PasswordResetRequestForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await wrapper.get("form").trigger("submit");

    expect(button(wrapper).attributes("disabled")).toBeDefined();
    expect(button(wrapper).text()).toBe("Sending…");

    pending.resolve(STATUS);
    await settle(wrapper);
    expect(button(wrapper).attributes("disabled")).toBeUndefined();
  });
});

describe("PasswordResetConfirmForm", () => {
  it("renders two new-password fields", () => {
    const wrapper = withClient(PasswordResetConfirmForm, stub({}), { token: "tok" });

    expect(wrapper.get("form").classes()).toEqual(["ea-form", "ea-password-reset-confirm"]);
    expect(wrapper.get("input[name='newPassword']").attributes("autocomplete")).toBe(
      "new-password",
    );
    expect(wrapper.get("input[name='confirmPassword']").attributes("autocomplete")).toBe(
      "new-password",
    );
    expect(button(wrapper).text()).toBe("Set new password");
  });

  it("calls passwordResetConfirm with the token and emits success", async () => {
    const client = stub({ passwordResetConfirm: vi.fn(() => Promise.resolve(STATUS)) });
    const wrapper = withClient(PasswordResetConfirmForm, client, { token: "tok-1" });

    await fill(wrapper, "newPassword", "next-password");
    await fill(wrapper, "confirmPassword", "next-password");
    await submit(wrapper);

    expect(client.passwordResetConfirm).toHaveBeenCalledWith({
      token: "tok-1",
      newPassword: "next-password",
    });
    expect(emitted(wrapper, "success")).toEqual([[STATUS]]);
  });

  it("rejects a mismatch client-side without calling the client", async () => {
    const client = stub({ passwordResetConfirm: vi.fn(() => Promise.resolve(STATUS)) });
    const wrapper = withClient(PasswordResetConfirmForm, client, { token: "tok-1" });

    await fill(wrapper, "newPassword", "next-password");
    await fill(wrapper, "confirmPassword", "typo");
    await submit(wrapper);

    expect(client.passwordResetConfirm).not.toHaveBeenCalled();
    expect(wrapper.get("[role='alert']").text()).toMatch(/do not match/);
    expect(wrapper.get("input[name='confirmPassword']").attributes("aria-invalid")).toBe("true");
    expect(wrapper.get("input[name='newPassword']").attributes("aria-invalid")).toBeUndefined();
    expect(emitted(wrapper, "error")).toHaveLength(1);
    expect(emitted(wrapper, "success")).toEqual([]);
  });

  it("renders the server failure in role='alert' and emits error", async () => {
    const cause = new Error("Reset token expired");
    const client = stub({ passwordResetConfirm: vi.fn(() => Promise.reject(cause)) });
    const wrapper = withClient(PasswordResetConfirmForm, client, { token: "tok-1" });

    await fill(wrapper, "newPassword", "next-password");
    await fill(wrapper, "confirmPassword", "next-password");
    await submit(wrapper);

    expect(wrapper.get("[role='alert']").text()).toBe("Reset token expired");
    expect(emitted(wrapper, "error")).toEqual([[cause]]);
  });

  it("disables submit while pending", async () => {
    const pending = deferred<StatusResponse>();
    const client = stub({ passwordResetConfirm: vi.fn(() => pending.promise) });
    const wrapper = withClient(PasswordResetConfirmForm, client, { token: "tok-1" });

    await fill(wrapper, "newPassword", "next-password");
    await fill(wrapper, "confirmPassword", "next-password");
    await wrapper.get("form").trigger("submit");

    expect(button(wrapper).attributes("disabled")).toBeDefined();
    expect(wrapper.get("form").attributes("aria-busy")).toBe("true");

    pending.resolve(STATUS);
    await settle(wrapper);
    expect(button(wrapper).attributes("disabled")).toBeUndefined();
  });
});

describe("MagicLinkForm", () => {
  it("renders a single email field", () => {
    const wrapper = withClient(MagicLinkForm, stub({}));

    expect(wrapper.get("form").classes()).toEqual(["ea-form", "ea-magic-link"]);
    expect(wrapper.get("input[name='email']").attributes("type")).toBe("email");
    expect(button(wrapper).text()).toBe("Send magic link");
  });

  it("calls magicLink.send and emits success", async () => {
    const client = stub({ magicLink: { send: vi.fn(() => Promise.resolve(STATUS)) } });
    const wrapper = withClient(MagicLinkForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(client.magicLink.send).toHaveBeenCalledWith({ email: "alice@vue.test" });
    expect(emitted(wrapper, "success")).toEqual([[STATUS]]);
  });

  it("renders the failure in role='alert' and emits error", async () => {
    const cause = new Error("Not Found");
    const client = stub({ magicLink: { send: vi.fn(() => Promise.reject(cause)) } });
    const wrapper = withClient(MagicLinkForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(wrapper.get("[role='alert']").text()).toBe("Not Found");
    expect(wrapper.get("input[name='email']").attributes("aria-invalid")).toBe("true");
    expect(emitted(wrapper, "error")).toEqual([[cause]]);
  });

  it("disables submit while pending", async () => {
    const pending = deferred<StatusResponse>();
    const client = stub({ magicLink: { send: vi.fn(() => pending.promise) } });
    const wrapper = withClient(MagicLinkForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await wrapper.get("form").trigger("submit");

    expect(button(wrapper).attributes("disabled")).toBeDefined();
    expect(wrapper.get("form").attributes("aria-busy")).toBe("true");

    pending.resolve(STATUS);
    await settle(wrapper);
    expect(button(wrapper).attributes("disabled")).toBeUndefined();
  });
});

describe("EmailOtpForm", () => {
  it("starts on the email step", () => {
    const wrapper = withClient(EmailOtpForm, stub({}));

    expect(wrapper.get("form").classes()).toEqual(["ea-form", "ea-email-otp"]);
    expect(wrapper.get("input[name='email']").attributes("type")).toBe("email");
    expect(wrapper.find("input[name='otp']").exists()).toBe(false);
    expect(button(wrapper).text()).toBe("Send code");
  });

  it("sends a code, swaps to the verify step, then signs in and emits success", async () => {
    const client = stub({
      emailOtp: {
        send: vi.fn(() => Promise.resolve(STATUS)),
        signIn: vi.fn(() => Promise.resolve(AUTH_SUCCESS)),
      },
    });
    const wrapper = withClient(EmailOtpForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(client.emailOtp.send).toHaveBeenCalledWith({
      email: "alice@vue.test",
      purpose: "sign-in",
    });
    expect(emitted(wrapper, "success")).toEqual([]);

    const code = wrapper.get("input[name='otp']");
    expect(code.attributes("autocomplete")).toBe("one-time-code");
    expect(code.attributes("inputmode")).toBe("numeric");
    expect(wrapper.find("input[name='email']").exists()).toBe(false);
    expect(button(wrapper).text()).toBe("Sign in");

    await fill(wrapper, "otp", "123456");
    await submit(wrapper);

    expect(client.emailOtp.signIn).toHaveBeenCalledWith({
      email: "alice@vue.test",
      otp: "123456",
    });
    expect(emitted(wrapper, "success")).toEqual([[AUTH_SUCCESS]]);
  });

  it("forwards the purpose prop to emailOtp.send", async () => {
    const client = stub({ emailOtp: { send: vi.fn(() => Promise.resolve(STATUS)) } });
    const wrapper = withClient(EmailOtpForm, client, { purpose: "email-verification" });

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(client.emailOtp.send).toHaveBeenCalledWith({
      email: "alice@vue.test",
      purpose: "email-verification",
    });
  });

  it("stays on the email step and reports a failed request", async () => {
    const cause = new Error("Not Found");
    const client = stub({ emailOtp: { send: vi.fn(() => Promise.reject(cause)) } });
    const wrapper = withClient(EmailOtpForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);

    expect(wrapper.get("[role='alert']").text()).toBe("Not Found");
    expect(wrapper.get("input[name='email']").attributes("aria-invalid")).toBe("true");
    expect(emitted(wrapper, "error")).toEqual([[cause]]);
  });

  it("reports a rejected code on the verify step", async () => {
    const cause = new Error("Invalid code");
    const client = stub({
      emailOtp: {
        send: vi.fn(() => Promise.resolve(STATUS)),
        signIn: vi.fn(() => Promise.reject(cause)),
      },
    });
    const wrapper = withClient(EmailOtpForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await submit(wrapper);
    await fill(wrapper, "otp", "000000");
    await submit(wrapper);

    expect(wrapper.get("[role='alert']").text()).toBe("Invalid code");
    expect(wrapper.get("input[name='otp']").attributes("aria-invalid")).toBe("true");
    expect(emitted(wrapper, "error")).toEqual([[cause]]);
  });

  it("disables submit while either step is pending", async () => {
    const pending = deferred<StatusResponse>();
    const client = stub({ emailOtp: { send: vi.fn(() => pending.promise) } });
    const wrapper = withClient(EmailOtpForm, client);

    await fill(wrapper, "email", "alice@vue.test");
    await wrapper.get("form").trigger("submit");

    expect(button(wrapper).attributes("disabled")).toBeDefined();
    expect(button(wrapper).text()).toBe("Sending…");
    expect(wrapper.get("form").attributes("aria-busy")).toBe("true");

    pending.resolve(STATUS);
    await settle(wrapper);

    expect(button(wrapper).attributes("disabled")).toBeUndefined();
    expect(wrapper.get("form").attributes("aria-busy")).toBe("false");
  });
});
