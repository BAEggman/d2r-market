-- v1 → v2 마이그레이션 (이미 배포한 D1에만 실행; 새 설치는 schema.sql 사용)
ALTER TABLE users ADD COLUMN rec_hash TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN rec_salt TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL REFERENCES users(id),
  to_id INTEGER NOT NULL REFERENCES users(id),
  listing_id INTEGER, body TEXT NOT NULL,
  created_at INTEGER NOT NULL, read_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_id, read_at);
CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(from_id, to_id, id);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL REFERENCES users(id),
  target_type TEXT NOT NULL CHECK (target_type IN ('listing','comment','user')),
  target_id INTEGER NOT NULL, reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, id DESC);
-- 관리자 지정(본인 아이디로 바꿔 실행): UPDATE users SET is_admin=1 WHERE username='본인아이디';
