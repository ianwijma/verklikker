CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY, subject text NOT NULL UNIQUE, name text NOT NULL,
  concurrency integer NOT NULL DEFAULT 4 CHECK(concurrency > 0),
  storage_limit bigint NOT NULL DEFAULT 107374182400,
  storage_used bigint NOT NULL DEFAULT 0, storage_reserved bigint NOT NULL DEFAULT 0,
  active integer NOT NULL DEFAULT 0 CHECK(active >= 0), last_scheduled timestamptz NOT NULL DEFAULT 'epoch',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS api_keys (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL,
  hash text NOT NULL, scopes text[] NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS runs (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), batch_id uuid,
  spec jsonb NOT NULL, state text NOT NULL DEFAULT 'queued', capture_health text NOT NULL DEFAULT 'pending',
  idempotency_key text, spec_hash text NOT NULL, attempt_id uuid, worker_id text, lease_hash text, lease_expires timestamptz,
  cancel_requested boolean NOT NULL DEFAULT false, exit_code integer, reason text, manifest jsonb,
  created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, ended_at timestamptz,
  UNIQUE(tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS runs_queue ON runs (tenant_id,created_at) WHERE state='queued';
CREATE INDEX IF NOT EXISTS runs_tenant ON runs (tenant_id,created_at DESC);
CREATE TABLE IF NOT EXISTS artifacts (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), run_id uuid REFERENCES runs(id),
  attempt_id uuid, name text NOT NULL, object_key text NOT NULL UNIQUE,
  size bigint NOT NULL CHECK(size >= 0), sha256 text NOT NULL, media_type text NOT NULL, kind text NOT NULL,
  committed boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS artifacts_run ON artifacts(run_id, committed);
CREATE TABLE IF NOT EXISTS pending_deletions (
  object_key text PRIMARY KEY, delete_after timestamptz NOT NULL DEFAULT now()+interval '16 minutes'
);
CREATE TABLE IF NOT EXISTS audit (
  id bigserial PRIMARY KEY, tenant_id uuid REFERENCES tenants(id), action text NOT NULL, details jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS run_updates (
  id bigserial PRIMARY KEY, run_id uuid NOT NULL REFERENCES runs(id), data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
