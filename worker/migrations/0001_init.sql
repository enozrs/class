-- Migration 0001: chat messages table for D1.
-- Capped at 20 rows at the application layer; the DB just stores what it's told.

CREATE TABLE IF NOT EXISTS messages (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  student_name TEXT    NOT NULL,
  message      TEXT    NOT NULL,
  created_at   INTEGER NOT NULL
);

-- Fast ORDER BY created_at DESC LIMIT 20 on every read.
CREATE INDEX IF NOT EXISTS idx_messages_created_at
  ON messages (created_at DESC);