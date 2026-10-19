-- Read all alert types without materializing another copy of the history.
CREATE OR REPLACE VIEW all_alerts AS
SELECT e.id, e.alert_type, e.alert_time, e.src_ip, e.dst_ip,
       e.severity, e.status, e.title, e.summary, e.source_service,
       CASE e.alert_type
         WHEN 'file' THEN to_jsonb(f)-'alert_id'
         WHEN 'account' THEN to_jsonb(a)-'alert_id'
         WHEN 'parasitic' THEN to_jsonb(p)-'alert_id'
       END AS details,
       r.payload_json AS raw_evidence
FROM alert_events e
LEFT JOIN file_alert_details f ON f.alert_id=e.id
LEFT JOIN account_alert_details a ON a.alert_id=e.id
LEFT JOIN parasitic_alert_details p ON p.alert_id=e.id
LEFT JOIN alert_raw_events r ON r.id=e.raw_event_id;
GRANT SELECT ON all_alerts TO honeypot_reader,honeypot_management;
INSERT INTO schema_migrations(version) VALUES ('003_all_alerts_view') ON CONFLICT DO NOTHING;
