# PostgreSQL 告警存储

## 部署与数据模型

只使用一个业务数据库 `honeypot`，部署在资源更充足的探针服务器 `43.163.94.52`。
PostgreSQL 16 只监听 `127.0.0.1:5432`。中心 `47.239.238.27` 通过 systemd 管理的
SSH 隧道 `127.0.0.1:15433` 访问它；公网不开放 5432。
探针上的蜜点进程仍通过 HTTP/gRPC 上报告警，不持有数据库密码。

`honeypot_ingest` 和 `honeypot_management` 是两个最小权限应用账号，不是两个数据库。
同一个库中保留接收、统一告警、证据和配置表，避免重复部署独立历史库。

| 表 | 用途 |
| --- | --- |
| alert_events | 所有类型统一告警，唯一事件 ID、时间、来源和幂等键 |
| all_alerts | 合并三类明细和原始证据的查询视图，不额外复制数据 |
| file_alert_details / account_alert_details / parasitic_alert_details | 通过 alert_id 外键关联的类型明细 |
| alert_raw_events | 与统一告警关联的原始证据；孤立记录清理 |
| account_alerts / trigger_infos | 接收端记录，供同步接口使用，同样限制数量 |
| device_fingerprints / bot_detections | 寄生蜜点指纹与检测观测，同样限制数量 |
| FileAlertInfo / account_alert_info / url_alert_info | 旧接口兼容记录，有限保留，不是独立数据库 |
| token_infos / honeyfiles / filedeploy / honeyaccount / honeyurl | 蜜点身份与部署配置，不按告警上限删除 |
| agent_client_info / agent_monitor_record / agent_control_log | 探针身份、审计和控制记录 |
| alert_retention_policy | 每类告警上限、保留时间字段与事务内数量计数 |
| storage_archive_batches / experiment_dataset_snapshots | 手动归档和实验快照清单 |

接收记录、原始证据和统一明细有不同用途，不应只因字段相同就删除。
界面及实验导出优先查询统一告警表；兼容表随旧统一事件清理，并有自己的数量上限。
JSON 模型字段保留 PostgreSQL JSON 类型，原始证据文本保留 TEXT。

## 每类最多 20 万条

文件、账户、寄生三类**分别**保留最新 200000 条统一告警，不是总共 20 万，
也不是每个 IP 或每个投放文件 20 万。排序为 `alert_time DESC, id DESC`。
事务提交时执行保留约束；新告警进入后删除最早告警及其明细、无引用原始证据和兼容记录。
延迟到达且早于保留边界的事件可能立即被淘汰，不能保证长时间停机后补回全部历史。

`002_bounded_retention.sql` 使用数量计数、事务行锁和延迟约束触发器；
新告警及明细写完后才淘汰，回滚也会回滚计数。首次应用前停写并完成备份。
接收/兼容表也有 20 万上限，防止统一表受限但上游副本无限增长。
账户查询已改为逐页处理和提交，不将整个历史窗口放进内存。

管理员可以在停写维护窗口修改 `alert_retention_policy.max_rows`，然后执行
`SELECT prune_alert_relation(table_name,alert_type) FROM alert_retention_policy`。
降低上限会永久删除在线历史。研究数据需提前导出固定快照；清单本身不会绕过保留规则。
不要直接 TRUNCATE 受管理表，否则会绕过行级计数；批量维护后应核对计数。

首次清理后执行 `VACUUM FULL ANALYZE` 回收旧占用；它会锁表，只在维护窗口运行。
平时 PostgreSQL autovacuum 回收死元组供复用，不对每次插入执行 VACUUM FULL。
20 万是条数限制，不是磁盘字节限额；大字段、WAL、备份和其他业务仍占空间。

## 初始化与迁移

环境变量 `ALERT_DATABASE_URL` / `SYSTEMWIRE_DATABASE_URL` 使用同一个库、不同账号。
密码从 `/etc/honeypot/*.env` 注入，不提交 Git。Flask 与 gRPC 共用连接配置。

1. 初始化角色、单库和表。Go 的 `ALERT_MIGRATE_ONLY=1` 仅建表，Python 使用 `init_management.py`。
2. 停写、冻结旧 SQLite，压缩备份并校验解压内容 SHA-256。
3. `migrate_sqlite.py` 导入空目标，逐表数量和规范化内容校验，失败整库回滚。
4. 合并两个接收/管理表集后，`verify_database.py` 再验证所有表内容，之后应用 001、002 SQL。
5. 验证三类触发、心跳、页面和实验导出，再退役旧在线库；保留切换前压缩备份。

历史无时区时间按北京时间解释。Go 纳秒转换为 PostgreSQL 微秒，旧备份保留原值。
密码等攻击者输入使用 TEXT，不能截断为 VARCHAR(255)。
参考 billing-backend 的显式 DDL、组合索引与归档清单，不复制其计费模型。

## 备份、容量与连接

每小时检查两台机器容量；使用率 >=80% 或剩余 <5 GiB 为 warning，
>=90% 或剩余 <2 GiB 为 critical，结果在 `/var/lib/honeypot/capacity.json`。
没有配置短信/邮件通知。探针数据库连接数 50、shared_buffers 256MB、work_mem 4MB，
应用连接池有限；中心和探针均不能因此被称为“无限容量”或“高可用”。

探针每日在数据库本机执行压缩 pg_dump，保留最近 7 次成功备份，再传输压缩文件到中心。
中心校验备份 SHA-256，只保留最近一次成功备份。避免未压缩数据跨机传输挤占应用连接。
切换前备份不在日常轮换目录内。
`storage.py archive` 提供额外的 JSONL.gz 导出和校验，不重复执行在线删除。
隧道断连由 systemd 重连，应用报错后重试；没有实施数据库主从切换。

本机管理：在探针执行 `sudo -u postgres psql -d honeypot`。
电脑连接：先运行 `ssh -N -L 15432:127.0.0.1:5432 zhangsan@43.163.94.52`。
Navicat/DBeaver：主机 `127.0.0.1`，端口 `15432`，库 `honeypot`，账号 `honeypot_reader`。
只读密码在探针 `/etc/honeypot/readonly.json`，用 sudo 查看，不粘贴到论文或 Git。
统一查询：`SELECT * FROM all_alerts ORDER BY alert_time DESC,id DESC LIMIT 100;`。
实验导出注入 `SYSTEMWIRE_DATABASE_URL`；连接失败明确报错，不读取旧 SQLite。

同库部署配置 `HONEYPOT_SINGLE_DATABASE=1`，应用 `004_account_batch_sync.sql` 后，
账户告警以固定大小批次在数据库内完成规范化和入库，使用源 ID 游标、相同幂等键和事务提交。
跨库/SQLite 开发环境仍使用分页 HTTP 同步。两种路径都不跳过失败批次或推进失败游标。
