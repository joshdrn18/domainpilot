-- Per-account Telegram notification settings.
CREATE TABLE IF NOT EXISTS dp_user_alert_settings (
  user_id TEXT PRIMARY KEY,
  telegram_chat_id TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES dp_users(id) ON DELETE CASCADE
);
