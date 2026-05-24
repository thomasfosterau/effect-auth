"use client";

import { useActionState } from "react";
import type { ConduitProfile } from "@/lib/server/types";
import { logoutAction, updateUserAction, type FormState } from "../actions";

export default function SettingsForm({ user }: { user: ConduitProfile }) {
  const [state, formAction] = useActionState<FormState, FormData>(updateUserAction, null);
  return (
    <div className="settings-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-6 offset-md-3 col-xs-12">
            <h1 className="text-xs-center">Your Settings</h1>
            {state?.errors && (
              <ul className="error-messages">
                {state.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <form action={formAction}>
              <fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control"
                    type="text"
                    name="image"
                    placeholder="URL of profile picture"
                    defaultValue={user.image ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control form-control-lg"
                    type="text"
                    name="username"
                    placeholder="Your Name"
                    defaultValue={user.username}
                    required
                  />
                </fieldset>
                <fieldset className="form-group">
                  <textarea
                    className="form-control form-control-lg"
                    rows={8}
                    name="bio"
                    placeholder="Short bio about you"
                    defaultValue={user.bio ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control form-control-lg"
                    type="email"
                    name="email"
                    placeholder="Email"
                    defaultValue={user.email}
                    required
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control form-control-lg"
                    type="password"
                    name="password"
                    placeholder="New Password (leave blank to keep)"
                  />
                </fieldset>
                <button className="btn btn-lg btn-primary pull-xs-right" type="submit">
                  Update Settings
                </button>
              </fieldset>
            </form>
            <hr />
            <form action={logoutAction}>
              <button className="btn btn-outline-danger" type="submit">
                Or click here to logout.
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
