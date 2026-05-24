<script lang="ts">
  let { form } = $props();
</script>

<div class="auth-page">
  <div class="container page">
    <div class="row">
      <div class="col-md-6 offset-md-3 col-xs-12">
        <h1 class="text-xs-center">Sign in</h1>
        <p class="text-xs-center"><a href="/register">Need an account?</a></p>

        {#if form?.errors}
          <ul class="error-messages">
            {#each form.errors as e (e)}<li>{e}</li>{/each}
          </ul>
        {/if}

        <form method="POST">
          <fieldset class="form-group">
            <input class="form-control form-control-lg" type="email" name="email" placeholder="Email" value={form?.email ?? ""} required />
          </fieldset>
          <fieldset class="form-group">
            <input class="form-control form-control-lg" type="password" name="password" placeholder="Password" required />
          </fieldset>
          <button class="btn btn-lg btn-primary pull-xs-right" type="submit">Sign in</button>
        </form>
      </div>
    </div>
  </div>
</div>
