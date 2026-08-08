-- D2R 장터 — D1 스키마 v2
-- 새로 설치: 이 파일 전체를 D1 콘솔에 붙여넣기 실행
-- 기존 v1 DB 업그레이드: migrate-v2.sql 사용

CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT NOT NULL COLLATE NOCASE UNIQUE,
  pass_hash  TEXT NOT NULL,
  salt       TEXT NOT NULL,
  battletag  TEXT DEFAULT '',
  rec_hash   TEXT DEFAULT '',
  rec_salt   TEXT DEFAULT '',
  is_admin   INTEGER NOT NULL DEFAULT 0,
  banned     INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS listings (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  type         TEXT NOT NULL CHECK (type IN ('sell','buy')),
  item_en      TEXT NOT NULL,
  item_ko      TEXT NOT NULL,
  title        TEXT DEFAULT '',
  options_text TEXT DEFAULT '',
  price_mode   TEXT NOT NULL DEFAULT 'runes' CHECK (price_mode IN ('runes','offer','text')),
  price_json   TEXT DEFAULT '[]',
  price_text   TEXT DEFAULT '',
  platform     TEXT NOT NULL DEFAULT 'pc'   CHECK (platform IN ('pc','switch','ps','xbox')),
  mode         TEXT NOT NULL DEFAULT 'sc'   CHECK (mode IN ('sc','hc')),
  ladder       TEXT NOT NULL DEFAULT 'non'  CHECK (ladder IN ('ladder','non')),
  version      TEXT NOT NULL DEFAULT 'rotw' CHECK (version IN ('classic','lod','rotw')),
  contact      TEXT DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','done','hidden')),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_listings_feed ON listings(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_listings_item ON listings(item_en);
CREATE INDEX IF NOT EXISTS idx_listings_user ON listings(user_id);

CREATE TABLE IF NOT EXISTS comments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  listing_id INTEGER NOT NULL REFERENCES listings(id),
  user_id    INTEGER NOT NULL REFERENCES users(id),
  body       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_listing ON comments(listing_id, id);

CREATE TABLE IF NOT EXISTS messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id    INTEGER NOT NULL REFERENCES users(id),
  to_id      INTEGER NOT NULL REFERENCES users(id),
  listing_id INTEGER,
  body       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_id, read_at);
CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(from_id, to_id, id);

CREATE TABLE IF NOT EXISTS reports (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL REFERENCES users(id),
  target_type TEXT NOT NULL CHECK (target_type IN ('listing','comment','user')),
  target_id   INTEGER NOT NULL,
  reason      TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, id DESC);

CREATE TABLE IF NOT EXISTS rate_limits (
  key      TEXT PRIMARY KEY,
  n        INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);
