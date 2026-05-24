<script lang="ts">
  import ArticleList from "$lib/components/ArticleList.svelte";

  let { data } = $props();

  let tab = $derived(data.tab);
  let tag = $derived(data.tag);
  let user = $derived(data.user);

  let baseHref = $derived(tag ? `/?tag=${encodeURIComponent(tag)}` : tab === "your" ? "/?tab=your" : "/?tab=global");
</script>

<div class="home-page">
  <div class="banner">
    <div class="container">
      <h1 class="logo-font">conduit</h1>
      <p>A place to share your knowledge.</p>
    </div>
  </div>

  <div class="container page">
    <div class="row">
      <div class="col-md-9">
        <div class="feed-toggle">
          <ul class="nav nav-pills outline-active">
            {#if user}
              <li class="nav-item">
                <a class={tab === "your" ? "nav-link active" : "nav-link"} href="/?tab=your">Your Feed</a>
              </li>
            {/if}
            <li class="nav-item">
              <a class={tab === "global" ? "nav-link active" : "nav-link"} href="/?tab=global">Global Feed</a>
            </li>
            {#if tag}
              <li class="nav-item">
                <a class="nav-link active" href={`/?tag=${tag}`}>#{tag}</a>
              </li>
            {/if}
          </ul>
        </div>

        <ArticleList
          articles={data.articles}
          articlesCount={data.articlesCount}
          offset={data.offset}
          limit={data.limit}
          baseHref={baseHref}
        />
      </div>

      <div class="col-md-3">
        <div class="sidebar">
          <p>Popular Tags</p>
          <div class="tag-list">
            {#each data.tags as t (t)}
              <a href={`/?tag=${encodeURIComponent(t)}`} class="tag-pill tag-default">{t}</a>
            {/each}
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
