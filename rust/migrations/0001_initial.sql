CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  picture TEXT,
  created_at INTEGER NOT NULL,
  last_login INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email);

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_login INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  version INTEGER NOT NULL DEFAULT 0,
  model TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','editor','viewer')),
  added_at INTEGER NOT NULL,
  PRIMARY KEY (project_id,email)
);

CREATE INDEX IF NOT EXISTS members_by_email ON members(email);

CREATE TABLE IF NOT EXISTS motors (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  filename TEXT NOT NULL,
  content TEXT NOT NULL,
  summary TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS motors_by_owner ON motors(owner_id);

CREATE TABLE IF NOT EXISTS edits (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  user_name TEXT NOT NULL,
  at INTEGER NOT NULL,
  minor INTEGER NOT NULL DEFAULT 0,
  changes TEXT NOT NULL,
  inverse TEXT NOT NULL,
  note TEXT,
  PRIMARY KEY (project_id,version)
);

CREATE TABLE IF NOT EXISTS snapshots (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  model TEXT NOT NULL,
  PRIMARY KEY (project_id,version)
);
