-- Run against honeypot_management. Event IDs and evidence foreign keys remain stable.
BEGIN;
CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS storage_archive_batches (
    batch_id text PRIMARY KEY,
    source_database text NOT NULL,
    source_table text NOT NULL,
    cutoff timestamptz NOT NULL,
    row_count bigint NOT NULL CHECK (row_count >= 0),
    archive_path text NOT NULL,
    sha256 char(64) NOT NULL,
    archive_bytes bigint NOT NULL CHECK (archive_bytes >= 0),
    status text NOT NULL CHECK (status IN ('verified', 'copied_offsite', 'restored')),
    created_at timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz NOT NULL,
    UNIQUE (source_database, source_table, archive_path)
);
COMMENT ON TABLE storage_archive_batches IS 'Verified archive inventory; export never deletes live evidence';
CREATE INDEX IF NOT EXISTS idx_archive_source_cutoff
    ON storage_archive_batches(source_database, source_table, cutoff);
CREATE TABLE IF NOT EXISTS experiment_dataset_snapshots (
    snapshot_id text PRIMARY KEY,
    manifest_path text NOT NULL,
    manifest_sha256 char(64) NOT NULL,
    start_time timestamptz NOT NULL,
    end_time timestamptz NOT NULL,
    event_count bigint NOT NULL CHECK (event_count >= 0),
    code_commit text NOT NULL,
    protected boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (end_time >= start_time)
);
COMMENT ON TABLE experiment_dataset_snapshots IS 'Research snapshot inventory; preserve artifacts referenced by published results';
INSERT INTO schema_migrations(version) VALUES ('001_storage_management') ON CONFLICT DO NOTHING;
COMMIT;
