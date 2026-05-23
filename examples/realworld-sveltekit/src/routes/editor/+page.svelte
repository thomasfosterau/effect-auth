<script lang="ts">
  let { form } = $props();
  type FailShape = { errors?: string[]; title?: string; description?: string; body?: string; tagList?: string };
  let f = $derived(form as FailShape | null);
</script>

<div class="editor-page">
  <div class="container page">
    <div class="row">
      <div class="col-md-10 offset-md-1 col-xs-12">
        {#if f?.errors}
          <ul class="error-messages">
            {#each f.errors as e (e)}<li>{e}</li>{/each}
          </ul>
        {/if}
        <form method="POST">
          <fieldset>
            <fieldset class="form-group">
              <input type="text" class="form-control form-control-lg" name="title" placeholder="Article Title" value={f?.title ?? ""} />
            </fieldset>
            <fieldset class="form-group">
              <input type="text" class="form-control" name="description" placeholder="What's this article about?" value={f?.description ?? ""} />
            </fieldset>
            <fieldset class="form-group">
              <textarea class="form-control" rows="8" name="body" placeholder="Write your article (in markdown)">{f?.body ?? ""}</textarea>
            </fieldset>
            <fieldset class="form-group">
              <input type="text" class="form-control" name="tagList" placeholder="Enter tags (space or comma separated)" value={f?.tagList ?? ""} />
            </fieldset>
            <button class="btn btn-lg pull-xs-right btn-primary" type="submit">Publish Article</button>
          </fieldset>
        </form>
      </div>
    </div>
  </div>
</div>
