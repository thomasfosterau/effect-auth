<script lang="ts">
  import ArticleList from "$lib/components/ArticleList.svelte";

  let { data } = $props();
  let p = $derived(data.profile);
  let me = $derived(data.user);
  let isMe = $derived(me && me.username === p.username);
</script>

<div class="profile-page">
  <div class="user-info">
    <div class="container">
      <div class="row">
        <div class="col-xs-12 col-md-10 offset-md-1">
          {#if p.image}<img src={p.image} class="user-img" alt="" />{/if}
          <h4>{p.username}</h4>
          {#if p.bio}<p>{p.bio}</p>{/if}

          {#if isMe}
            <a href="/settings" class="btn btn-sm btn-outline-secondary action-btn">
              <i class="ion-gear-a"></i> Edit Profile Settings
            </a>
          {:else if me}
            <form method="POST" action={p.following ? "?/unfollow" : "?/follow"} style="display:inline">
              <button class="btn btn-sm btn-outline-secondary action-btn" type="submit">
                <i class="ion-plus-round"></i> {p.following ? "Unfollow" : "Follow"} {p.username}
              </button>
            </form>
          {/if}
        </div>
      </div>
    </div>
  </div>

  <div class="container">
    <div class="row">
      <div class="col-xs-12 col-md-10 offset-md-1">
        <div class="articles-toggle">
          <ul class="nav nav-pills outline-active">
            <li class="nav-item"><a class={data.tab === "my" ? "nav-link active" : "nav-link"} href={`/profile/${p.username}`}>My Articles</a></li>
            <li class="nav-item"><a class={data.tab === "favorites" ? "nav-link active" : "nav-link"} href={`/profile/${p.username}?tab=favorites`}>Favorited Articles</a></li>
          </ul>
        </div>
        <ArticleList
          articles={data.articles}
          articlesCount={data.articlesCount}
          offset={0}
          limit={10}
          baseHref={`/profile/${p.username}${data.tab === "favorites" ? "?tab=favorites" : ""}`}
        />
      </div>
    </div>
  </div>
</div>
