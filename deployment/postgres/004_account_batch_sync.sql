-- Keep bulk normalization inside the single database, avoiding raw-data round trips.
CREATE OR REPLACE FUNCTION sync_account_alert_batch(since_time timestamptz, before_id bigint, batch_size integer DEFAULT 500)
RETURNS TABLE(next_id bigint, inserted bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE last_id bigint; added bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(640019);
    DROP TABLE IF EXISTS pg_temp.account_sync_batch;
    CREATE TEMP TABLE account_sync_batch ON COMMIT DROP AS
    SELECT a.*,
      'account|'||concat_ws('|',lower(trim(coalesce(src_ip,''))),lower(trim(coalesce(dst_ip,''))),
        lower(trim(coalesce(username,''))),lower(trim(coalesce(protocol,''))),lower(trim(coalesce(message,''))),
        floor(extract(epoch FROM trigger_time))::bigint::text) AS event_key,
      nextval('account_alert_info_id_seq') AS legacy_id,
      nextval('alert_raw_events_id_seq') AS raw_id,
      nextval('alert_events_id_seq') AS event_id,
      json_build_object('id',id,'trigger_time',trigger_time,'report_time',report_time,
        'src_ip',src_ip,'src_port',src_port,'dst_ip',dst_ip,'dst_port',dst_port,
        'username',username,'password',password,'client_version',client_version,
        'protocol',protocol,'message',message,'raw_event',raw_event) AS payload
    FROM account_alerts a
    WHERE a.deleted_at IS NULL AND a.id<before_id
      AND (since_time IS NULL OR a.trigger_time>since_time)
    ORDER BY a.id DESC LIMIT greatest(1,least(batch_size,1000));
    SELECT min(id) INTO last_id FROM account_sync_batch;
    DELETE FROM account_sync_batch b WHERE EXISTS(SELECT 1 FROM alert_events e WHERE e.dedupe_key=b.event_key);
    DELETE FROM account_sync_batch b USING account_sync_batch newer
      WHERE b.event_key=newer.event_key AND b.id<newer.id;
    ALTER TABLE account_sync_batch ADD COLUMN attack_type text;
    UPDATE account_sync_batch SET attack_type=CASE
      WHEN lower(coalesce(message,'')) LIKE '%password%' OR lower(payload::text) LIKE '%request with password%' THEN 'SSH 密码认证尝试'
      WHEN lower(payload::text||coalesce(client_version,'')) SIMILAR TO '%(request with key|keytype|fingerprint)%' THEN 'SSH 公钥认证尝试'
      WHEN lower(coalesce(protocol,'ssh'))='ssh' THEN 'SSH 登录探测'
      ELSE upper(coalesce(protocol,'ssh'))||' 访问尝试' END;
    INSERT INTO account_alert_info(id,trigger_time,report_time,src_ip,src_port,dst_ip,dst_port,username,password,client_version,protocol,message,raw_event)
      SELECT legacy_id,trigger_time,report_time,src_ip,src_port,dst_ip,dst_port,username,password,client_version,coalesce(protocol,'ssh'),message,payload FROM account_sync_batch;
    INSERT INTO alert_raw_events(id,source_service,source_event_id,payload_json)
      SELECT raw_id,'alert_server','ingest-account-'||id,payload::text FROM account_sync_batch;
    INSERT INTO alert_events(id,alert_type,source_service,source_event_id,honeypot_name,alert_time,src_ip,dst_ip,severity,status,title,summary,raw_event_id,dedupe_key,legacy_table,legacy_row_id)
      SELECT event_id,'account','alert_server','ingest-account-'||id,'账户蜜点',trigger_time,src_ip,dst_ip,
        CASE WHEN attack_type LIKE '%密码%' OR attack_type LIKE '%公钥%' THEN 'high' ELSE 'medium' END,
        'new',attack_type,coalesce(nullif(src_ip,''),'-')||CASE WHEN src_port<>'' THEN ':'||src_port ELSE '' END||
        ' -> '||coalesce(nullif(dst_ip,''),'-')||CASE WHEN dst_port<>'' THEN ':'||dst_port ELSE '' END||' / '||coalesce(nullif(username,''),'-'),
        raw_id,event_key,'account_alert_info',legacy_id FROM account_sync_batch;
    GET DIAGNOSTICS added=ROW_COUNT;
    INSERT INTO account_alert_details(alert_id,protocol,username,password,src_port,dst_port,client_version,client_family,auth_type,message,raw_event_json)
      SELECT event_id,protocol,username,password,src_port,dst_port,client_version,
        CASE WHEN lower(client_version) LIKE '%openssh%' THEN 'OpenSSH 客户端'
             WHEN lower(client_version) LIKE '%finalshell%' THEN 'FinalShell'
             WHEN lower(client_version) SIMILAR TO '%(nsssh|netsarang|xshell)%' THEN 'Xshell / NetSarang'
             WHEN lower(client_version) LIKE '%putty%' THEN 'PuTTY' ELSE '未知 SSH 客户端' END,
        attack_type,message,payload::text FROM account_sync_batch;
    RETURN QUERY SELECT last_id,added;
END $$;
REVOKE ALL ON FUNCTION sync_account_alert_batch(timestamptz,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sync_account_alert_batch(timestamptz,bigint,integer) TO honeypot_management;
INSERT INTO schema_migrations(version) VALUES ('004_account_batch_sync') ON CONFLICT DO NOTHING;
