<script lang="ts">
  let { data, form } = $props();
  let a = $derived(data.article);
</script>

<div class="editor-page">
  <div class="container page">
    <div class="row">
      <div class="col-md-10 offset-md-1 col-xs-12">
        {#if form?.errors}
          <ul class="error-messages">
            {#each form.errors as e (e)}<li>{e}</li>{/each}
          </ul>
        {/if}
        <form method="POST">
          <fieldset>
            <fieldset class="form-group">
              <input type="text" class="form-control form-control-lg" name="title" value={a.title} />
            </fieldset>
            <fieldset class="form-group">
              <input type="text" class="form-control" name="description" value={a.description} />
            </fieldset>
            <fieldset class="form-group">
              <textarea class="form-control" rows="8" name="body">{a.body}</textarea>
            </fieldset>
            <button class="btn btn-lg pull-xs-right btn-primary" type="submit">Update Article</button>
          </fieldset>
        </form>
      </div>
    </div>
  </div>
</div>
