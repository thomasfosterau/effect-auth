"use client";

import { useActionState } from "react";
import { loginAction, type FormState } from "../actions";

export default function LoginPage() {
  const [state, formAction] = useActionState<FormState, FormData>(loginAction, null);
  return (
    <div className="auth-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-6 offset-md-3 col-xs-12">
            <h1 className="text-xs-center">Sign in</h1>
            <p className="text-xs-center">
              <a href="/register">Need an account?</a>
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
                  placeholder="Password"
                  required
                />
              </fieldset>
              <button className="btn btn-lg btn-primary pull-xs-right" type="submit">
                Sign in
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
