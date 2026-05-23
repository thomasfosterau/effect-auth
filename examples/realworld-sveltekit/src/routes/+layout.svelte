<script lang="ts">
  import { page } from "$app/state";

  let { data, children } = $props();
  let user = $derived(data.user);
  let path = $derived(page.url.pathname);

  function active(href: string) {
    return path === href ? "nav-link active" : "nav-link";
  }
</script>

<nav class="navbar navbar-light">
  <div class="container">
    <a class="navbar-brand" href="/">conduit</a>
    <ul class="nav navbar-nav pull-xs-right">
      <li class="nav-item">
        <a class={active("/")} href="/">Home</a>
      </li>
      {#if user}
        <li class="nav-item">
          <a class={active("/editor")} href="/editor">
            <i class="ion-compose"></i>&nbsp;New Article
          </a>
        </li>
        <li class="nav-item">
          <a class={active("/settings")} href="/settings">
            <i class="ion-gear-a"></i>&nbsp;Settings
          </a>
        </li>
        <li class="nav-item">
          <a class={active(`/profile/${user.username}`)} href={`/profile/${user.username}`}>
            {#if user.image}<img class="user-pic" src={user.image} alt="" />{/if}
            {user.username}
          </a>
        </li>
      {:else}
        <li class="nav-item">
          <a class={active("/login")} href="/login">Sign in</a>
        </li>
        <li class="nav-item">
          <a class={active("/register")} href="/register">Sign up</a>
        </li>
      {/if}
    </ul>
  </div>
</nav>

{@render children()}

<footer>
  <div class="container">
    <a href="/" class="logo-font">conduit</a>
    <span class="attribution">
      An interactive learning project from <a href="https://thinkster.io">Thinkster</a>. Code &amp; design licensed under MIT — implemented with
      <a href="https://github.com/thomasfosterau/effect-auth">effect-auth</a> on SvelteKit.
    </span>
  </div>
</footer>
