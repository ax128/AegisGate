# 网关高并发能力分析

## 1. 结论概览

| 维度 | 现状 | 高并发下表现 |
|------|------|----------------|
| **能否应对高并发？** | **有限**。单进程、同步阻塞 I/O、默认线程池与单库，适合中小流量；未针对高并发优化。 | 需改造成本（见下文）。 |
| **主要瓶颈** | ① 上游调用阻塞线程 ② 单进程单库 ③ SQLite 写并发 | 随 QPS 上升，延迟与排队明显。 |
| **建议** | 中小流量（如 &lt;50 并发）可直接用；高并发需异步化 + 多进程/多实例 + 存储与连接池优化。 | 按目标 QPS 选方案。 |

---

## 2. 当前架构中的并发相关点

### 2.1 请求处理模型

- **FastAPI 入口**：中间件为 `async`，但业务路由为 **同步** `def`：
  - `chat_completions(payload, request)`、`responses(payload, request)` 均为 `def`。
- **Starlette/FastAPI 行为**：同步视图会在**线程池**中执行（默认约 40 线程，与实现版本有关），不会阻塞 asyncio 事件循环，但**每个正在处理的请求会占满一个线程**，直到该请求完成。

因此：**并发度上限 ≈ 线程池大小**（单进程内）。若每个请求平均占用线程 3s（含上游等待），单进程理论 QPS 约 40/3 ≈ 13 req/s，且排队会随并发增加而拉高延迟。

### 2.2 上游调用：同步阻塞

- **实现**：`_forward_json` 使用 `urllib.request.urlopen()`，**同步阻塞**等待上游完整响应。
- **影响**：单次请求占用线程时间 = 网关内处理 + **上游 LLM 响应时间**（常见 1–10s）。高并发时大量线程被阻塞在 I/O，吞吐受限于「线程数 / 平均响应时间」。

```python
# router.py
with urlopen(upstream_req, timeout=settings.upstream_timeout_seconds) as resp:
    return resp.status, _decode_json_or_text(resp.read())
```

### 2.3 存储层：SQLite 单库、无连接池

- **SqliteKVStore**：每次读写使用 `_connect()` 新建连接，执行完即关闭，**无连接池**。
- **并发控制**：使用 `threading.Lock` 保护内存 cache；DB 层使用 WAL、`busy_timeout=5000`、`_with_retry` 应对锁冲突。
- **影响**：SQLite 单写多读，高并发写（如大量 redaction + pending confirmation）会出现锁等待与重试，延迟与尾分位上升。

### 2.4 共享状态与线程安全

- **NonceReplayCache**：`threading.Lock` 保护，**线程安全**。
- **SqliteKVStore**：内存 cache 有锁；多线程同时写 DB 依赖 SQLite 的 busy_timeout 与重试，**可工作但非高并发优化**。
- **全局单例**：`store`、`policy_engine` 等为模块级单例，多线程共享；若仅读配置、写 DB 通过锁/重试，**无额外竞态**，但 DB 成为瓶颈。

### 2.5 部署形态

- **README / Docker**：默认 `uvicorn ... app`，**单 worker**；Docker 单容器单进程。
- **影响**：单进程内并发受上述线程池与 SQLite 限制；多核无法利用，无法水平扩展。

---

## 3. 瓶颈归纳

| 瓶颈 | 原因 | 高并发下表现 |
|------|------|----------------|
| **线程占用时间长** | 同步 `urlopen` 等待上游 1–10s | 线程池被占满，新请求排队，P99 延迟上升 |
| **单进程** | uvicorn 默认 1 worker | 单机多核未用，吞吐有天花板 |
| **SQLite** | 单库、单写、无连接池 | 写多时锁竞争与重试，延迟抖动 |
| **无上游连接复用** | 每次 `urlopen` 新建连接 | 上游若为 HTTP/1.1 无法复用，连接数、握手开销随 QPS 增加 |

---

## 4. 可承受的并发量（经验估计）

在**默认配置**（单 worker、同步路由、SQLite、单实例）下：

- **粗略上限**：约 **10–20 并发** 可较稳定运行（视上游延迟与 SQLite 写比例而定）；**50+ 并发** 易出现明显排队与延迟上升。
- **主要变量**：上游平均响应时间、是否启用 HMAC（CPU）、redaction/restoration 与 pending 的写比例。

**不视为**「高并发架构」：未使用异步 I/O、多 worker/多实例、连接池、外部数据库或缓存。

---

## 5. 处理建议

### 5.1 建议总览

| 优先级 | 建议项 | 适用场景 | 预期效果 |
|--------|--------|----------|----------|
| **P0** | 异步上游调用 | 所有希望提升并发的场景 | 单进程并发不再受线程数限制，吞吐可上一个数量级 |
| **P0** | 请求 body / 消息条数 / 长度限制 | 与长上下文、大 payload 并存时 | 降低单请求占用与 DB 压力，见《长上下文与大文件处理》 |
| **P1** | 多 worker 或多实例 | 单机多核、目标 QPS &gt; 20 | 线性提升吞吐；多实例时需解决 Nonce/存储共享 |
| **P1** | 存储外迁 + 连接池 | SQLite 写多、锁竞争明显 | 减少 DB 瓶颈与连接开销 |
| **P2** | Nonce 集中式（如 Redis） | 多实例部署 | 跨实例防重放 |
| **P2** | 审计异步/队列写 | 高 QPS 下审计成为瓶颈时 | 避免写文件阻塞请求 |

### 5.2 立即可做（无需改代码）

- **限制并发入口**：在网关前加反向代理（如 Nginx），按 IP 或 key 做并发/速率限制，避免单实例过载。
- **调大线程池**：若暂时不改异步，可适当调大 Starlette 运行同步视图的线程池大小（需查当前版本配置方式），仅缓解排队，无法根本消除阻塞。
- **单实例多 worker**：`uvicorn ... --workers 2` 或 4；注意多进程下 SQLite 写冲突，建议仅只读或单 worker 写，或先迁出 SQLite。

### 5.3 短期改造（改网关代码）

- **异步上游**：用 `httpx.AsyncClient` 替代 `urlopen`，路由改为 `async def`，在等待上游处 `await`；设置连接池上限（如 `max_connections=100`）。
- **入口限制**：在 router 或中间件中增加请求 body 大小、messages 条数、单条 content 长度检查，超限返回 413/400；与《长上下文与大文件处理》中的建议一致，减轻单请求资源占用。

### 5.4 中期改造（架构与存储）

- **存储外迁**：将 pending_confirmation、mapping_store 迁到 PostgreSQL 或 Redis，使用连接池；多实例共享同一存储。
- **Nonce 集中式**：多实例时用 Redis（或其它集中式缓存）存 nonce+timestamp，替代进程内 `NonceReplayCache`，保证防重放跨实例生效。
- **审计异步化**：审计事件先写入内存队列或消息队列，后台 worker 落盘或投递日志服务，避免请求路径直接写文件。

### 5.5 改造要点详解（与上表对应）

- **异步上游调用（P0）**：将 `_forward_json` 改为基于 **async HTTP 客户端**（如 `httpx.AsyncClient`），路由改为 `async def`，在等待上游时 **await**，不占用线程；单进程内可同时挂起大量等待上游的协程，并发度由上游连接数与内存决定。
- **多 worker / 多实例（P1）**：uvicorn `--workers 4` 或多容器 + 负载均衡；若仍用 SQLite，建议单实例单写或迁移到 PostgreSQL/Redis。
- **存储与连接池（P1）**：pending 与映射存储迁至 PostgreSQL/Redis 并做连接池；上游使用 httpx 时配置 `limits=httpx.Limits(max_connections=100)`。
- **Nonce 与审计（P2）**：多实例下 Nonce 改为 Redis 等集中式；审计高 QPS 时改为异步写或队列落盘。

---

## 6. 针对当前项目的处理方案

以下结合**当前 AegisGate 代码与部署形态**，给出可直接落地的处理方案：**不改代码**与**需改代码**分开，便于按阶段实施。

### 6.1 不改代码可做的（部署与运维）

| 措施 | 实施方式 | 针对当前项目的说明 |
|------|----------|----------------------|
| **反向代理限流** | 在网关前加 Nginx/Caddy，对转发的 `/v1/*`、`/relay/*` 做 `limit_conn`、`limit_req`，按 IP 或 token 限并发/速率 | 当前无内置限流，代理层限制可防止单实例被压垮；与《长上下文与大文件处理》中的 body 限制可一并配置 |
| **多 worker 提升吞吐** | 启动时改为 `uvicorn aegisgate.core.gateway:app --workers 2`（或 4），多进程 | 当前 README/Docker 为单 worker；多 worker 后**注意**：SQLite 文件被多进程写会锁冲突，redaction mapping 与 pending_confirmation 仍写同一 DB，建议先观察锁与重试，若频繁冲突再考虑 6.2 存储外迁或仅 1 个 worker 写（需改代码区分读写） |
| **Docker 资源限制** | 在 `docker-compose.yml` 中为 aegisgate 服务设 `deploy.resources.limits.memory`、`cpus` | 当前无 limits；设上限后单实例 OOM 或 CPU 打满不会拖垮宿主机，便于配合代理限流做容量规划 |
| **监控与告警** | 对网关端口或代理的 QPS、延迟、5xx 率做采集；对 `logs/audit.jsonl` 或应用日志做简单统计 | 当前无内置 metrics 端点，可先基于访问日志与审计日志做“请求量/延迟分布”观测，发现瓶颈后再决定是否上异步或存储外迁 |

### 6.2 需改代码的处理方案（要动哪、怎么动）

以下仅说明**优化哪部分代码、怎么优化**，不直接修改代码。

| 目标 | 要改的位置 | 怎么改 | 预期效果 |
|------|------------|--------|----------|
| **异步上游，释放线程** | `aegisgate/adapters/openai_compat/router.py`：`_forward_json`、`chat_completions`/`responses` 及内部调用的 `_execute_chat_once`/`_execute_responses_once` | 用 `httpx.AsyncClient`（或 aiohttp）替代 `urllib.request.urlopen`，在发上游处 `await client.post(...)`；将 `chat_completions`/`responses` 改为 `async def`，内部 `await _execute_*`；启动时若用 uvicorn 需保证 asyncio 驱动（默认即可） | 单进程内并发不再受线程池约 40 限制，可挂起大量等待上游的协程，吞吐显著提升 |
| **上游连接池** | 同上，在创建 `httpx.AsyncClient` 时配置 `limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)`，且 client 复用（模块级或请求级复用同一 client） | 避免每次请求新建连接，降低上游与网关的连接数与握手开销 |
| **入口 body/条数/长度限制** | `aegisgate/adapters/openai_compat/router.py` 在解析 `payload` 后、`aegisgate/config/settings.py` 增加配置项 | 在 `chat_completions`/`responses` 开头检查 body 大小、`len(messages)`、单条 content 长度，超限返回 400/413；详见《长上下文与大文件处理》第 5 节代码优化建议 | 单请求占用与 DB 压力下降，有利于并发下稳定 |
| **存储外迁（减轻 SQLite 锁）** | `aegisgate/storage/sqlite_store.py` 的接口保持不变，新增 `aegisgate/storage/postgres_store.py` 或 `redis_store.py` 实现同一套接口（如 `set_mapping`/`get_mapping`/`consume_mapping`、`save_pending_confirmation`/`get_pending_confirmation`/`update_pending_confirmation_status`/`prune_pending_confirmations`/`get_latest_pending_confirmation`）；`router.py` 中通过配置或依赖注入选择 store 实现 | 多实例或高写并发下用 PostgreSQL/Redis 替代 SQLite，连接池 + 无单点锁，延迟与尾分位更稳 |
| **Nonce 集中式（多实例防重放）** | `aegisgate/core/security_boundary.py` 的 `NonceReplayCache` 改为从 Redis（或其它集中式缓存）读写的实现，或增加一层 `RedisNonceCache`；`aegisgate/core/gateway.py` 中根据配置选择使用进程内 cache 还是 Redis | 多实例部署时 nonce 共享，防重放跨实例生效 |
| **审计异步写** | `aegisgate/core/audit.py` 的 `write_audit`：改为将事件 put 到内存队列（如 `queue.Queue`）或消息队列，后台线程/worker 从队列取事件再写文件或投递日志服务；或先写内存缓冲，定时 flush 到文件 | 高 QPS 下写文件不阻塞请求线程，降低 P99 延迟 |

### 6.3 按目标 QPS 的选型建议（当前项目）

| 目标 | 不改代码可做 | 建议优先改代码 |
|------|----------------|----------------|
| **&lt;20 并发、&lt;10 QPS** | 反向代理限流 + Docker 资源限制即可 | 可不改 |
| **约 20–50 QPS** | 代理限流 + 多 worker（2～4）+ 资源限制 | **异步上游** + 上游连接池；若 SQLite 锁明显再考虑存储外迁 |
| **&gt;50 QPS 或多实例** | 代理限流 + 多实例 + 负载均衡 + 资源限制 | **异步上游** + **存储外迁** + **Nonce 集中式**；审计视情况异步化 |

---

## 7. 小结

- **当前网关**：适合**中小并发**（例如 &lt;20 并发、&lt;10 QPS 量级），**不能**视为高并发就绪。
- **主要限制**：同步阻塞上游调用 + 单进程 + SQLite 单库，导致线程占满、排队与 DB 锁竞争。
- **若要高并发**：优先 **异步上游（async + httpx）**，辅以 **多 worker/多实例** 与 **存储/连接池/Nonce 共享** 等，按目标 QPS 分阶段改造。
- **针对当前项目**：不改代码时可做代理限流、多 worker、Docker 资源限制与监控（见第 6.1 节）；需改代码时见第 6.2 节（具体文件与改法）与第 6.3 节（按目标 QPS 选型）。
