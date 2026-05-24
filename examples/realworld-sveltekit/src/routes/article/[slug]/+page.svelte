<script lang="ts">
  let { data } = $props();
  let a = $derived(data.article);
  let me = $derived(data.user);
  let isAuthor = $derived(me && me.username === a.author.username);
</script>

<div class="article-page">
  <div class="banner">
    <div class="container">
      <h1>{a.title}</h1>
      <div class="article-meta">
        <a href={`/profile/${a.author.username}`}>
          {#if a.author.image}<img src={a.author.image} alt="" />{/if}
        </a>
        <div class="info">
          <a href={`/profile/${a.author.username}`} class="author">{a.author.username}</a>
          <span class="date">{new Date(a.createdAt).toDateString()}</span>
        </div>

        {#if isAuthor}
          <a href={`/editor/${a.slug}`} class="btn btn-sm btn-outline-secondary">
            <i class="ion-edit"></i> Edit Article
          </a>
          &nbsp;
          <form method="POST" action="?/delete" style="display:inline">
            <button class="btn btn-sm btn-outline-danger" type="submit">
              <i class="ion-trash-a"></i> Delete Article
            </button>
          </form>
        {:else if me}
          <form method="POST" action={a.author.following ? "?/unfollow" : "?/follow"} style="display:inline">
            <input type="hidden" name="username" value={a.author.username} />
            <button class="btn btn-sm btn-outline-secondary" type="submit">
              <i class="ion-plus-round"></i> {a.author.following ? "Unfollow" : "Follow"} {a.author.username}
            </button>
          </form>
          &nbsp;
          <form method="POST" action={a.favorited ? "?/unfavorite" : "?/favorite"} style="display:inline">
            <button class={`btn btn-sm ${a.favorited ? "btn-primary" : "btn-outline-primary"}`} type="submit">
              <i class="ion-heart"></i> {a.favorited ? "Unfavorite" : "Favorite"} Article ({a.favoritesCount})
            </button>
          </form>
        {/if}
      </div>
    </div>
  </div>

  <div class="container page">
    <div class="row article-content">
      <div class="col-md-12">
        <p style="white-space: pre-wrap">{a.body}</p>
        {#if a.tagList.length > 0}
          <ul class="tag-list">
            {#each a.tagList as t (t)}<li class="tag-default tag-pill tag-outline">{t}</li>{/each}
          </ul>
        {/if}
      </div>
    </div>

    <hr />

    <div class="row">
      <div class="col-xs-12 col-md-8 offset-md-2">
        {#if me}
          <form class="card comment-form" method="POST" action="?/comment">
            <div class="card-block">
              <textarea class="form-control" name="body" placeholder="Write a comment..." rows="3"></textarea>
            </div>
            <div class="card-footer">
              {#if me.image}<img src={me.image} class="comment-author-img" alt="" />{/if}
              <button class="btn btn-sm btn-primary" type="submit">Post Comment</button>
            </div>
          </form>
        {:else}
          <p><a href="/login">Sign in</a> or <a href="/register">sign up</a> to add comments on this article.</p>
        {/if}

        {#each data.comments as c (c.id)}
          <div class="card">
            <div class="card-block">
              <p class="card-text">{c.body}</p>
            </div>
            <div class="card-footer">
              <a href={`/profile/${c.author.username}`} class="comment-author">
                {#if c.author.image}<img src={c.author.image} class="comment-author-img" alt="" />{/if}
              </a>
              &nbsp;
              <a href={`/profile/${c.author.username}`} class="comment-author">{c.author.username}</a>
              <span class="date-posted">{new Date(c.createdAt).toDateString()}</span>
              {#if me && me.username === c.author.username}
                <form method="POST" action="?/deleteComment" style="display:inline; float:right">
                  <input type="hidden" name="id" value={c.id} />
                  <button class="mod-options" type="submit" aria-label="Delete comment"><i class="ion-trash-a"></i></button>
                </form>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    </div>
  </div>
</div>
