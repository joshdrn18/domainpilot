-- DomainPilot automated monitoring and alert history.
-- All objects are isolated with dp_ names in the shared D1 database.

CREATE TABLE IF NOT EXISTS dp_ssl_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id TEXT NOT NULL,
  status TEXT NOT NULL,
  issuer TEXT,
  not_after TEXT,
  days_remaining INTEGER,
  source TEXT NOT NULL DEFAULT 'crt.sh',
  details TEXT,
  checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS dp_ssl_checks_latest_idx
  ON dp_ssl_checks(domain_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS dp_alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id TEXT,
  owner_id TEXT,
  alert_key TEXT NOT NULL UNIQUE,
  alert_type TEXT NOT NULL,
  message TEXT NOT NULL,
  delivery_status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  sent_at TEXT
);
CREATE INDEX IF NOT EXISTS dp_alert_events_created_idx
  ON dp_alert_events(created_at DESC);

CREATE TABLE IF NOT EXISTS dp_monitor_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_type TEXT NOT NULL,
  checked_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  details TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT
);
