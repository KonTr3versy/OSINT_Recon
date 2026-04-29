CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  company TEXT,
  allowed_mode TEXT NOT NULL DEFAULT 'passive',
  dns_policy_ceiling TEXT NOT NULL DEFAULT 'minimal',
  third_party_intel_allowed INTEGER NOT NULL DEFAULT 0,
  default_schedule TEXT NOT NULL DEFAULT '0 9 * * 1',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assets_org_domain ON assets (org_id, domain);

CREATE TABLE IF NOT EXISTS recon_plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  asset_id INTEGER NOT NULL,
  requested_mode TEXT NOT NULL,
  requested_dns_policy TEXT NOT NULL,
  enable_third_party_intel INTEGER NOT NULL DEFAULT 0,
  budgets_json TEXT NOT NULL,
  expected_sources_json TEXT NOT NULL,
  requires_approval INTEGER NOT NULL DEFAULT 0,
  approval_status TEXT NOT NULL DEFAULT 'approved',
  rationale TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_recon_plans_org_asset ON recon_plans (org_id, asset_id);

CREATE TABLE IF NOT EXISTS approval_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  recon_plan_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  reason TEXT NOT NULL,
  decision_note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_org_status ON approval_requests (org_id, status);

CREATE TABLE IF NOT EXISTS recon_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  asset_id INTEGER NOT NULL,
  recon_plan_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  payload_json TEXT NOT NULL,
  result_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_recon_jobs_org_status ON recon_jobs (org_id, status);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id INTEGER,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_org_action ON audit_events (org_id, action);

CREATE TABLE IF NOT EXISTS run_summaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  recon_job_id INTEGER NOT NULL,
  asset_id INTEGER NOT NULL,
  artifact_prefix TEXT,
  summary_json TEXT NOT NULL,
  agent_summary TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
