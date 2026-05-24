<script lang="ts">
  let { data, form } = $props();
</script>

<div class="settings-page">
  <div class="container page">
    <div class="row">
      <div class="col-md-6 offset-md-3 col-xs-12">
        <h1 class="text-xs-center">Your Settings</h1>

        {#if form?.errors}
          <ul class="error-messages">
            {#each form.errors as e (e)}<li>{e}</li>{/each}
          </ul>
        {/if}

        <form method="POST" action="?/update">
          <fieldset>
            <fieldset class="form-group">
              <input class="form-control" type="text" name="image" placeholder="URL of profile picture" value={data.user.image ?? ""} />
            </fieldset>
            <fieldset class="form-group">
              <input class="form-control form-control-lg" type="text" name="username" placeholder="Your Name" value={data.user.username} required />
            </fieldset>
            <fieldset class="form-group">
              <textarea class="form-control form-control-lg" rows="8" name="bio" placeholder="Short bio about you">{data.user.bio ?? ""}</textarea>
            </fieldset>
            <fieldset class="form-group">
              <input class="form-control form-control-lg" type="email" name="email" placeholder="Email" value={data.user.email} required />
            </fieldset>
            <fieldset class="form-group">
              <input class="form-control form-control-lg" type="password" name="password" placeholder="New Password (leave blank to keep)" />
            </fieldset>
            <button class="btn btn-lg btn-primary pull-xs-right" type="submit">Update Settings</button>
          </fieldset>
        </form>

        <hr />

        <form method="POST" action="?/logout">
          <button class="btn btn-outline-danger" type="submit">Or click here to logout.</button>
        </form>
      </div>
    </div>
  </div>
</div>
