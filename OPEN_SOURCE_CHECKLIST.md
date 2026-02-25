# 开源上传 GitHub 前检查清单

本文档用于上传前自检，**docs/ 与 DOC/ 已加入 .gitignore，不会随仓库上传**。

## 1. 已处理项

- [x] **docs / DOC 不上传**：`.gitignore` 已包含 `docs/` 与 `DOC/`
- [x] **运行数据不上传**：`logs/*`、`*.db`、`*.log` 已忽略，仅保留 `logs/.gitkeep`
- [x] **本地密钥不上传**：`.env`、`.env.*` 已忽略，保留 `.env.example` 作为模板
- [x] **内部 URL 替换**：README 与测试中的示例上游已改为通用地址（如 `your-upstream.example.com`），无内部域名
- [x] **LICENSE**：已添加 MIT License
- [x] **.env.example**：已提供环境变量模板，无真实密钥

## 2. 上传前建议再确认

- [ ] **AEGIS_GATEWAY_KEY**：`docker-compose.yml` 与 `settings.py` 默认值为 `agent`，仅适合本地/演示；README 中已说明生产必须设置强密钥，可考虑在 README 再次强调「生产环境务必修改」
- [ ] **postgres DSN**：`settings.py` 中 `postgres_dsn` 含默认 `postgres:postgres`，仅为本地开发示例，未写入 .env.example 的敏感值，可保留
- [ ] **运行一次测试**：`pytest -q` 确保通过后再 push
- [ ] **清理本地**：确认无 `logs/*.db`、`logs/audit.jsonl`、`.env` 被误 add

## 3. 可选优化（非必须）

- [ ] **README 顶部**：可加一句「生产部署请务必修改 `AEGIS_GATEWAY_KEY` 并配置 HMAC 等」
- [ ] **CONTRIBUTING.md**：若希望接受外部贡献，可增加贡献指南与 PR 流程
- [ ] **SECURITY.md**：可添加安全披露策略（如漏洞反馈方式）
- [ ] **GitHub 仓库设置**：设置默认分支、Description、Topics（如 llm, gateway, security, openai-compatible）

## 4. 上传命令示例

```bash
git init
git add .
git status   # 再次确认无 docs/、.env、logs 下数据库/日志被加入
git commit -m "feat: open source AegisGate LLM security gateway"
git remote add origin https://github.com/YOUR_ORG/AegisGate.git
git push -u origin main
```
