"use client";

import { useActionState } from "react";
import { publishArticleAction, type FormState } from "../actions";

export default function EditorForm() {
  const [state, formAction] = useActionState<FormState, FormData>(publishArticleAction, null);
  const v = state?.values ?? {};
  return (
    <div className="editor-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-10 offset-md-1 col-xs-12">
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
                    type="text"
                    className="form-control form-control-lg"
                    name="title"
                    placeholder="Article Title"
                    defaultValue={v.title ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control"
                    name="description"
                    placeholder="What's this article about?"
                    defaultValue={v.description ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <textarea
                    className="form-control"
                    rows={8}
                    name="body"
                    placeholder="Write your article (in markdown)"
                    defaultValue={v.body ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control"
                    name="tagList"
                    placeholder="Enter tags (space or comma separated)"
                    defaultValue={v.tagList ?? ""}
                  />
                </fieldset>
                <button className="btn btn-lg pull-xs-right btn-primary" type="submit">
                  Publish Article
                </button>
              </fieldset>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
