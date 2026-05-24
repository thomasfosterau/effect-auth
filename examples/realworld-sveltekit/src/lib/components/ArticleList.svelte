<script lang="ts">
  import type { ConduitArticle } from "$lib/server/types";

  let { articles, articlesCount, offset, limit, baseHref }: {
    articles: ConduitArticle[];
    articlesCount: number;
    offset: number;
    limit: number;
    baseHref: string;
  } = $props();

  let pages = $derived(Math.max(1, Math.ceil(articlesCount / limit)));
  let current = $derived(Math.floor(offset / limit));

  function pageHref(i: number) {
    const sep = baseHref.includes("?") ? "&" : "?";
    return `${baseHref}${sep}offset=${i * limit}`;
  }
</script>

{#if articles.length === 0}
  <div class="article-preview">No articles are here... yet.</div>
{:else}
  {#each articles as a (a.slug)}
    <div class="article-preview">
      <div class="article-meta">
        <a href={`/profile/${a.author.username}`}>
          {#if a.author.image}<img src={a.author.image} alt="" />{/if}
        </a>
        <div class="info">
          <a href={`/profile/${a.author.username}`} class="author">{a.author.username}</a>
          <span class="date">{new Date(a.createdAt).toDateString()}</span>
        </div>
        <button class={`btn btn-sm pull-xs-right ${a.favorited ? "btn-primary" : "btn-outline-primary"}`}>
          <i class="ion-heart"></i> {a.favoritesCount}
        </button>
      </div>
      <a href={`/article/${a.slug}`} class="preview-link">
        <h1>{a.title}</h1>
        <p>{a.description}</p>
        <span>Read more...</span>
        {#if a.tagList.length > 0}
          <ul class="tag-list">
            {#each a.tagList as t (t)}
              <li class="tag-default tag-pill tag-outline">{t}</li>
            {/each}
          </ul>
        {/if}
      </a>
    </div>
  {/each}

  {#if pages > 1}
    <ul class="pagination">
      {#each Array(pages) as _, i (i)}
        <li class={`page-item ${i === current ? "active" : ""}`}>
          <a class="page-link" href={pageHref(i)}>{i + 1}</a>
        </li>
      {/each}
    </ul>
  {/if}
{/if}
