-- One database, bounded online history. Apply after a verified backup.
BEGIN;
CREATE TABLE IF NOT EXISTS alert_retention_policy (
    table_name text NOT NULL,
    alert_type text NOT NULL DEFAULT '',
    time_column text NOT NULL,
    max_rows bigint NOT NULL DEFAULT 200000 CHECK (max_rows > 0),
    live_rows bigint NOT NULL DEFAULT 0 CHECK (live_rows >= 0),
    PRIMARY KEY (table_name, alert_type)
);

INSERT INTO alert_retention_policy(table_name,alert_type,time_column) VALUES
 ('alert_events','file','alert_time'),
 ('alert_events','account','alert_time'),
 ('alert_events','parasitic','alert_time'),
 ('account_alerts','','trigger_time'),
 ('trigger_infos','','trigger_time'),
 ('device_fingerprints','','timestamp'),
 ('bot_detections','','timestamp'),
 ('account_alert_info','','trigger_time'),
 ('FileAlertInfo','','trigger_time'),
 ('url_alert_info','','trigger_time')
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION retention_track_count() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE delta integer;
BEGIN
    delta := CASE WHEN TG_OP='DELETE' THEN -1 ELSE 1 END;
    IF TG_TABLE_NAME='alert_events' THEN
        UPDATE alert_retention_policy p SET live_rows=p.live_rows+delta*x.n
          FROM (SELECT alert_type,count(*) AS n FROM changed_rows GROUP BY alert_type) x
          WHERE p.table_name=TG_TABLE_NAME AND p.alert_type=x.alert_type;
    ELSE
        UPDATE alert_retention_policy p SET live_rows=p.live_rows+delta*x.n
          FROM (SELECT count(*) AS n FROM changed_rows) x
          WHERE p.table_name=TG_TABLE_NAME AND p.alert_type='' AND x.n>0;
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION retention_delete_dependents() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
BEGIN
    DELETE FROM file_alert_details WHERE alert_id=OLD.id;
    DELETE FROM account_alert_details WHERE alert_id=OLD.id;
    DELETE FROM parasitic_alert_details WHERE alert_id=OLD.id;
    RETURN OLD;
END $$;

CREATE OR REPLACE FUNCTION retention_delete_unreferenced() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
BEGIN
    DELETE FROM alert_raw_events r WHERE r.id=OLD.raw_event_id
      AND NOT EXISTS(SELECT 1 FROM alert_events e WHERE e.raw_event_id=r.id);
    IF OLD.legacy_table IN ('FileAlertInfo','account_alert_info','url_alert_info')
       AND OLD.legacy_row_id IS NOT NULL
       AND NOT EXISTS(SELECT 1 FROM alert_events e
                      WHERE e.legacy_table=OLD.legacy_table AND e.legacy_row_id=OLD.legacy_row_id) THEN
        EXECUTE format('DELETE FROM %I WHERE id=$1',OLD.legacy_table) USING OLD.legacy_row_id;
    END IF;
    RETURN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_alert_events_legacy_reference ON alert_events(legacy_table,legacy_row_id);
DROP TRIGGER IF EXISTS retention_dependents ON alert_events;
CREATE TRIGGER retention_dependents BEFORE DELETE ON alert_events
 FOR EACH ROW EXECUTE FUNCTION retention_delete_dependents();
DROP TRIGGER IF EXISTS retention_unreferenced ON alert_events;
CREATE TRIGGER retention_unreferenced AFTER DELETE ON alert_events
 FOR EACH ROW EXECUTE FUNCTION retention_delete_unreferenced();

CREATE OR REPLACE FUNCTION prune_alert_relation(relation_name text, kind text DEFAULT '') RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE policy alert_retention_policy%ROWTYPE; removed bigint; total_removed bigint:=0;
BEGIN
    SELECT * INTO policy FROM alert_retention_policy
      WHERE table_name=relation_name AND alert_type=kind FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Unknown retention relation'; END IF;
    WHILE policy.live_rows > policy.max_rows LOOP
        IF relation_name='alert_events' THEN
            DELETE FROM alert_events WHERE id IN (
              SELECT id FROM alert_events WHERE alert_type=kind
              ORDER BY alert_time,id LIMIT least(policy.live_rows-policy.max_rows,10000));
        ELSE
            EXECUTE format('DELETE FROM %I WHERE id IN (SELECT id FROM %I ORDER BY %I,id LIMIT $1)',
                           relation_name,relation_name,policy.time_column)
              USING least(policy.live_rows-policy.max_rows,10000);
        END IF;
        GET DIAGNOSTICS removed=ROW_COUNT;
        IF removed=0 THEN RAISE EXCEPTION 'Retention counter mismatch'; END IF;
        total_removed:=total_removed+removed;
        SELECT * INTO policy FROM alert_retention_policy
          WHERE table_name=relation_name AND alert_type=kind;
    END LOOP;
    RETURN total_removed;
END $$;

-- Deferred until the event and its detail rows have all been written.
CREATE OR REPLACE FUNCTION retention_at_commit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE kind text := '';
BEGIN
    IF TG_TABLE_NAME='alert_events' THEN kind:=NEW.alert_type; END IF;
    PERFORM prune_alert_relation(TG_TABLE_NAME,kind);
    RETURN NULL;
END $$;

DO $$
DECLARE p record; n bigint;
BEGIN
    FOR p IN SELECT * FROM alert_retention_policy ORDER BY table_name,alert_type LOOP
        IF p.table_name='alert_events' THEN
            SELECT count(*) INTO n FROM alert_events WHERE alert_type=p.alert_type;
        ELSE
            EXECUTE format('SELECT count(*) FROM %I',p.table_name) INTO n;
        END IF;
        UPDATE alert_retention_policy SET live_rows=n
          WHERE table_name=p.table_name AND alert_type=p.alert_type;
        EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(%I,id)',
                       'idx_retention_'||lower(p.table_name),p.table_name,p.time_column);
    END LOOP;
    FOR p IN SELECT DISTINCT table_name FROM alert_retention_policy LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS retention_count ON %I',p.table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS retention_count_insert ON %I',p.table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS retention_count_delete ON %I',p.table_name);
        EXECUTE format('CREATE TRIGGER retention_count_insert AFTER INSERT ON %I REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION retention_track_count()',p.table_name);
        EXECUTE format('CREATE TRIGGER retention_count_delete AFTER DELETE ON %I REFERENCING OLD TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION retention_track_count()',p.table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS retention_limit ON %I',p.table_name);
        EXECUTE format('CREATE CONSTRAINT TRIGGER retention_limit AFTER INSERT ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION retention_at_commit()',p.table_name);
    END LOOP;
END $$;

REVOKE ALL ON alert_retention_policy FROM PUBLIC;
GRANT SELECT ON alert_retention_policy TO honeypot_ingest,honeypot_management,honeypot_reader;
REVOKE EXECUTE ON FUNCTION prune_alert_relation(text,text) FROM PUBLIC;
INSERT INTO schema_migrations(version) VALUES ('002_bounded_retention') ON CONFLICT DO NOTHING;
COMMIT;

-- First execution is maintenance: writers must be stopped.
SELECT table_name,alert_type,prune_alert_relation(table_name,alert_type) AS deleted
 FROM alert_retention_policy ORDER BY table_name,alert_type;
DELETE FROM alert_raw_events r WHERE NOT EXISTS(SELECT 1 FROM alert_events e WHERE e.raw_event_id=r.id);
