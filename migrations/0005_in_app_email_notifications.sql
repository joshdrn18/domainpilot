-- DomainPilot in-app notifications and email preferences.
CREATE TABLE IF NOT EXISTS dp_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id TEXT NOT NULL,
  domain_id TEXT,
  alert_key TEXT NOT NULL UNIQUE,
  alert_type TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  read_at TEXT,
  email_status TEXT NOT NULL DEFAULT 'pending',
  email_sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(owner_id) REFERENCES dp_users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS dp_notifications_owner_created_idx ON dp_notifications(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS dp_notifications_email_idx ON dp_notifications(email_status, created_at);
CREATE TABLE IF NOT EXISTS dp_user_notification_settings (
  user_id TEXT PRIMARY KEY,
  email_enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES dp_users(id) ON DELETE CASCADE
);
