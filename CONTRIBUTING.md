# 贡献指南（Contributing）

感谢你愿意为 RedHawk 贡献！请花几分钟阅读以下指南。

## 🛡️ 重要：使用与贡献边界

RedHawk 是**授权安全测试专用工具**。贡献代码前请确认：
- 你理解并同意 [DISCLAIMER.md](DISCLAIMER.md) 的全部条款
- 你贡献的内容**不会**帮助未授权攻击
- 不提交任何真实目标数据、凭据、攻击记录

## 🧑‍💻 开发环境

```bash
git clone <your-fork>
cd RedHawk/src
pip install -e .
pip install pytest
python -m pytest tests/ -v   # 全部通过再提 PR
```

## 🚦 提交流程

1. Fork 仓库，创建功能分支：`git checkout -b feat/xxx`
2. 提交前运行全部测试（119 个必须全绿）
3. 提交信息用中文或英文，说明改动目的
4. 发起 PR 到 `main` 分支，描述改动内容与测试结果

## 🔧 可以贡献的方向

| 方向 | 说明 |
|---|---|
| 🧰 新工具适配器 | `src/redhawk/adapters/` 下新增，遵循 BaseAdapter 契约（≤100 行） |
| 📜 playbook 模板 | `src/redhawk/playbooks/` 下加 YAML，加流程=加文件 |
| 🤖 AI 提示词 | `auto_pentest.py` / `ai_service.py` 中的 prompt 优化 |
| 🐛 Bug 修复 | 附带回归测试 |
| 🎨 前端 | `static/index.html` 体验改进 |
| 📚 文档 | README / 使用指南 / 截图 |

## ✅ 代码规范

- Python 3.10+，类型注解
- 每个新功能必须有测试
- 保持"绝对简洁"：不引入不必要依赖
- 适配器输出统一 JSON

## 📝 提交信息建议

```
feat: 新增 xxx 适配器
fix: 修复 xxx 问题
docs: 更新使用指南
test: 补充 xxx 测试
```

再次感谢！🦅
