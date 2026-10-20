-- HTTP requests are observations, not browser fingerprints or file-open alerts.
BEGIN;
CREATE TABLE IF NOT EXISTS web_access_observations (
    event_id text PRIMARY KEY,
    observed_at timestamptz NOT NULL,
    src_ip inet NOT NULL,
    host text NOT NULL,
    server_port integer NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    status integer NOT NULL,
    bytes_sent bigint NOT NULL,
    duration_ms double precision NOT NULL,
    user_agent text NOT NULL,
    observation_kind text NOT NULL,
    diagnostic_marker text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_web_observations_time ON web_access_observations(observed_at DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_web_observations_kind_time ON web_access_observations(observation_kind, observed_at DESC);
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='honeypot_web_observer') THEN
        CREATE ROLE honeypot_web_observer LOGIN;
    END IF;
END $$;
GRANT CONNECT ON DATABASE honeypot TO honeypot_web_observer;
GRANT USAGE ON SCHEMA public TO honeypot_web_observer;
GRANT SELECT,INSERT,DELETE ON web_access_observations TO honeypot_web_observer;
GRANT SELECT ON web_access_observations TO honeypot_management,honeypot_reader;
COMMIT;
