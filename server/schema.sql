-- Usuários (você e a pessoa que cadastra os anúncios)
CREATE TABLE IF NOT EXISTS users (
  username   TEXT PRIMARY KEY,
  salt       TEXT NOT NULL,
  hash       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Itens: kind='product' (biblioteca) ou kind='listing' (anúncio em andamento)
CREATE TABLE IF NOT EXISTS items (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  name       TEXT,
  status     TEXT,
  data       TEXT NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  updated_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_items_kind    ON items(kind);
CREATE INDEX IF NOT EXISTS idx_items_updated ON items(updated_at);
