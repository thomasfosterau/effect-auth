"use client";

import { useActionState } from "react";
import type { ConduitArticle } from "@/lib/server/types";
import { editArticleAction, type FormState } from "../../actions";

export default function EditForm({ article }: { article: ConduitArticle }) {
  const [state, formAction] = useActionState<FormState, FormData>(editArticleAction, null);
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
              <input type="hidden" name="slug" value={article.slug} />
              <fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control form-control-lg"
                    name="title"
                    defaultValue={article.title}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control"
                    name="description"
                    defaultValue={article.description}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <textarea
                    className="form-control"
                    rows={8}
                    name="body"
                    defaultValue={article.body}
                  />
                </fieldset>
                <button className="btn btn-lg pull-xs-right btn-primary" type="submit">
                  Update Article
                </button>
              </fieldset>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
