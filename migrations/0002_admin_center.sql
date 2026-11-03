-- DomainPilot Admin Center migration.
-- Applied to the shared domain-expiry-db D1 database on 2026-11-03.
-- All objects are isolated with dp_ names; existing reminder/bot tables are untouched.

ALTER TABLE dp_users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE dp_domains ADD COLUMN owner_id TEXT REFERENCES dp_users(id);

CREATE INDEX IF NOT EXISTS dp_domains_owner_idx ON dp_domains(owner_id);

CREATE TABLE IF NOT EXISTS dp_plans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain_limit INTEGER NOT NULL,
  monitoring_enabled INTEGER NOT NULL DEFAULT 0,
  custom_alerts INTEGER NOT NULL DEFAULT 0,
  price_monthly INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dp_user_plans (
  user_id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL DEFAULT 'free',
  expires_at TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES dp_users(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO dp_plans (id,name,domain_limit,monitoring_enabled,custom_alerts,price_monthly,active)
VALUES ('free','Free',5,0,0,0,1),('pro','Pro',100,1,1,0,1),('unlimited','Admin Unlimited',-1,1,1,0,1);

UPDATE dp_domains
SET owner_id=(SELECT id FROM dp_users WHERE role='admin' ORDER BY created_at LIMIT 1)
WHERE owner_id IS NULL;

INSERT OR IGNORE INTO dp_user_plans (user_id,plan_id)
SELECT id, CASE WHEN role='admin' THEN 'unlimited' ELSE 'free' END FROM dp_users;
