-- The example business table behind /api/notes. Replace it with your own.
CREATE TABLE notes (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
  body TEXT NOT NULL DEFAULT '',
  author_sub TEXT NOT NULL,
  author_email TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX notes_created_at ON notes (created_at);
