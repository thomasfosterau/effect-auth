"use client";

import { useActionState } from "react";
import { registerAction, type FormState } from "../actions";

export default function RegisterPage() {
  const [state, formAction] = useActionState<FormState, FormData>(registerAction, null);
  return (
    <div className="auth-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-6 offset-md-3 col-xs-12">
            <h1 className="text-xs-center">Sign up</h1>
            <p className="text-xs-center">
              <a href="/login">Have an account?</a>
            </p>
            {state?.errors && (
              <ul className="error-messages">
                {state.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <form action={formAction}>
              <fieldset className="form-group">
                <input
                  className="form-control form-control-lg"
                  type="text"
                  name="username"
                  placeholder="Username"
                  defaultValue={state?.values?.username ?? ""}
                  required
                />
              </fieldset>
              <fieldset className="form-group">
                <input
                  className="form-control form-control-lg"
                  type="email"
                  name="email"
                  placeholder="Email"
                  defaultValue={state?.values?.email ?? ""}
                  required
                />
              </fieldset>
              <fieldset className="form-group">
                <input
                  className="form-control form-control-lg"
                  type="password"
                  name="password"
                  placeholder="Password (8+ characters)"
                  minLength={8}
                  required
                />
              </fieldset>
              <button className="btn btn-lg btn-primary pull-xs-right" type="submit">
                Sign up
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
