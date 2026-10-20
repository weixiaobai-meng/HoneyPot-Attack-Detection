# 公网蜜点入口与 Web 观测

本组件改善可发现性并记录访问漏斗，不承诺吸引定向攻击，也不把普通请求自动当作恶意行为。2026-10-20 的已部署结果见 `ACCEPTANCE-20261020.md`。

## 已部署路径

- 探针 `43.163.94.52`：仓库 `/opt/honeypot/repo`，Nginx 80/8080 提供 `/var/www/honeypot` 静态入口；账户蜜点监听 2222。
- 中心 `47.239.238.27`：仓库 `/root/HoneyPot-Attack-Detection`，Nginx 80 的 IP 专用虚拟主机代理管理服务 5001。原有域名站点保留。
- `/downloads/<数字ID>` 仅代理中心的蜜文件下载接口；`/cdn/`、`/socket`、`/static/img/`、`/contact/` 代理中心告警接收服务 9090。
- PostgreSQL `honeypot` 在探针本机，中心通过已有 SSH 隧道 `127.0.0.1:15433` 连接。不需要开放 PostgreSQL 公网端口。
- 原有独立文件服务 7005 保留，没有被新的入口替换。

## 组件

- `render.py` 从真实文件目录 JSON 生成静态 HTML。无需 JavaScript 即可发现下载链接；目录变化后需重新渲染并安装 `index.html`。
- `telemetry.js` 上报浏览器实际采集信息和交互；不伪造 WebRTC 地址。
- `observe_access.py` 读取 Nginx JSON 日志，向独立 `web_access_observations` 表写入访问观测。数据库提交后才推进检查点；重放依靠请求 ID 唯一键去重。
- `005_web_observations.sql` 创建观测表和最小权限角色。前提是现有 `honeypot_management`、`honeypot_reader` 角色已存在。
- `honeypot-web-observer.service` 使用本机 peer 认证，无数据库明文密码，随系统启动、故障重启。只清理该观测表：最近 30 天、最多 200000 条；不清理业务告警表。
- 管理端统一告警使用数据库分页和检索。观测页面独立展示，不混入文件打开、账户、寄生三类正式告警。

## 运维与安全

探针应检查 `nginx`、`postgresql`、`honeypot-agent`、`honeypot-account`、`honeypot-web-observer`；中心检查 `nginx`、`systemwire2`、`alert_server`、`honeypot-db-tunnel` 的 `is-active` 和 `is-enabled`。

日志：`journalctl -u honeypot-web-observer`、`/var/log/nginx/honeypot-observations.log`。检查点：`/var/lib/honeypot-web-observer/state.json`。采集器读取当前日志和 `.1`，适合现有 Nginx rename/create + delaycompress 轮转；若停机超过多次轮转，应先保留旧日志再人工补采，不能宣称永不丢失。

管理端继续要求登录；未启用本地免认证开关。当前入口为 HTTP，正式长期使用应配置域名 HTTPS 或通过 SSH 隧道访问，避免在不可信网络直接传输管理口令/会话。不要在报告、命令历史或仓库中保存服务器密码、API key、临时会话 Cookie。

如用户本机代理导致 502，给 `43.163.94.52` 和 `47.239.238.27` 设置直连。首次入口验收使用浏览器级 bypass；后续经用户授权配置这两个 IP 直连，并用系统默认代理设置的 Edge 复验。

## 分析边界

普通实时/受控分析默认最多 2000 条，超限在加载前拒绝。平衡分析从每类最近最多 300 条候选里选取，默认每类最多 30 条；不足不补造。单进程交互分析互斥，忙时返回 429；这不是多 worker 分布式锁。

管理端允许已知 128 维旧 DQN checkpoint 严格兼容推理，并明确标记旧版模式；198 维当前结构按其原结构加载，未知结构或损坏权重仍显式回退。旧模型推理、规则回退、平衡样本和 LLM 报告均不能代替正式的 DQN 消融及规模实验，详见 `../ANALYSIS_REPAIR_20261020.md`。中心 `DEEPSEEK_MAX_TOKENS` 已设为 6000。LLM 报告若 `finish_reason=length`，界面会提示不完整；可通过现有服务环境调整上限后重启服务并重试。

自然观测、明确标记的验收流量、独立受控场景应分别统计。文件下载不是文件打开，HTTP 回连也不自动证明恶意；同源 IP 关联不是因果证据。

## 验证

在仓库根目录执行 `python -m unittest deployment.public_portal.test_portal -v`。8 项离线测试只写临时文件，不向业务数据库插入模拟告警。

上线需额外验证：真实浏览器遥测、真实 Office 文件回连、账户蜜点认证尝试，各自在业务库和登录后的 UI 出现；仅看端口或进程不能替代这些验收。

## 回退

两台服务器的本次备份目录均为 `/var/backups/honeypot/20261020-public-portal/`。

- 中心 `center-before.tar.gz` 保存原管理端源码、原 `systemwire2/config/config.py`、蜜文件和原导出脚本；`nginx-before.tar.gz` 保存原 Nginx 配置；`honeyfile-metadata.sql` 是文件元数据备份。
- 中心 `systemwire.env.before-report-limit` 是修改报告输出上限前的环境文件备份，包含凭据，权限 0600，不应展示或提交到 Git。
- 探针 `probe-before.tar.gz` 保存原 Nginx/入口；原默认站点链接另存为 `nginx-default-enabled`。
- 回退前先保存当前改动，检查压缩包清单，只恢复本次涉及的文件；不要整包覆盖现有域名站点或当前数据库。
- 先停止新增观测服务，再恢复相关入口配置；通过 `nginx -t` 后 reload，恢复管理端源码/配置后重启 `systemwire2`。源码新增文件可保留但不再引用。
- 不自动恢复旧业务数据库、不删除已入库告警和观测；需要回退蜜文件元数据时单独审查 SQL 与当前文件的对应关系。

正式发布流程：将本次源代码提交并推送至 GitHub `weime`，备份两端已有补丁后同步到同一提交，保留未跟踪/忽略的运行配置、数据库、模型权重和分析产物。验收需同时核对 GitHub、本地及两端 HEAD，检查已跟踪文件无差异，并确认上述服务 active/enabled。自启动指 systemd 开机启动和故障重启，不代表自动拉取任意后续 Git 提交；未进行整机重启时，不声称完成重启验收。
