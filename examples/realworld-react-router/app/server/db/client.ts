import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { resolve } from "node:path";
import * as schema from "./schema";

const DB_PATH = process.env.CONDUIT_DB ?? resolve(process.cwd(), "conduit.db");

const globalForDb = globalThis as unknown as {
  __conduitDb?: BetterSQLite3Database<typeof schema>;
};

function createDb() {
  const sqlite = new Database(DB_PATH);
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  const d = drizzle(sqlite, { schema });
  migrate(sqlite);
  return d;
}

function migrate(sqlite: Database.Database) {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bio TEXT,
      image TEXT,
      created_at INTEGER NOT NULL DEFAULT (unixepoch('now', 'subsec') * 1000)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_activity_at INTEGER NOT NULL,
      attributes TEXT
    );
    CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS articles (
      id TEXT PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      body TEXT NOT NULL,
      author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL DEFAULT (unixepoch('now', 'subsec') * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch('now', 'subsec') * 1000)
    );
    CREATE INDEX IF NOT EXISTS articles_author_idx ON articles(author_id);
    CREATE INDEX IF NOT EXISTS articles_created_idx ON articles(created_at);
    CREATE TABLE IF NOT EXISTS tags (name TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS article_tags (
      article_id TEXT NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
      tag TEXT NOT NULL REFERENCES tags(name) ON DELETE CASCADE,
      PRIMARY KEY (article_id, tag)
    );
    CREATE INDEX IF NOT EXISTS article_tags_tag_idx ON article_tags(tag);
    CREATE TABLE IF NOT EXISTS favorites (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      article_id TEXT NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, article_id)
    );
    CREATE INDEX IF NOT EXISTS favorites_article_idx ON favorites(article_id);
    CREATE TABLE IF NOT EXISTS follows (
      follower_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      following_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (follower_id, following_id)
    );
    CREATE INDEX IF NOT EXISTS follows_following_idx ON follows(following_id);
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      article_id TEXT NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
      author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (unixepoch('now', 'subsec') * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch('now', 'subsec') * 1000)
    );
    CREATE INDEX IF NOT EXISTS comments_article_idx ON comments(article_id);
  `);
}

export const db: BetterSQLite3Database<typeof schema> = globalForDb.__conduitDb ?? createDb();
if (process.env.NODE_ENV !== "production") globalForDb.__conduitDb = db;

export { schema };
export type DB = typeof db;
