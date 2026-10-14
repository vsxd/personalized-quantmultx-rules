# 让 Codex 检查并维护上游更新

本仓库维护自己的服务分类、例外规则和策略边界。上游提供候选变更及出处，不直接决定本仓库的分流行为。以后可在本仓库聊天中直接说：

> 检查其他规则仓库最新规则，按本仓库的分类和策略维护要求，有选择地更新我的规则，验证后整理变更。

按用户约定，“检查下别的规则仓库最新规则”“检查其他规则仓库最新规则”等简写默认包含比较、证据审查、选择性更新本仓库及验证；不需要再次询问是否更新。只有明确说“只检查”“不修改”等只读范围时，才停留在比较报告。是否提交、推送、创建 PR 按本次用户授权执行。任何仓库更新都不会自动导入 Quantumult X、切换策略或重连正在运行的 VPN。

## 1. 固定检查对象并保留工作区

先读 `AGENTS.md`、`upstream-lock.json`、`THIRD_PARTY.md`，以及 `docs/rule-categories.json`、`docs/category-partition.md`、`docs/quarantine.json`。执行 `git status --short`，保留已有修改，不用 reset 或全目录覆盖清理工作区。检查 `master` 是否仍为发布分支；不要因为上游叫 `main` 就修改本仓库订阅 URL。

使用 Python 3.10+ 和 git：

```sh
python3 scripts/check_upstreams.py
```

也可以限制检查范围：

```sh
python3 scripts/check_upstreams.py --source sve1r
python3 scripts/check_upstreams.py --source ppmina
```

脚本通过 `git ls-remote` 获取最新分支 SHA，再从完整 SHA 下载内容，不依赖 GitHub API 配额。生成的报告、原始文件和规则清单位于忽略目录 `work/upstream-check/<UTC时间戳>/`，不写入现有规则、配置或锁文件。不执行下载的 JavaScript、安装脚本或上游工作流。

检查范围：

- sve1r 的 `develop`，对比锁文件中 `files` 的真实上游路径，并包含 `repair_reference` 中的 Bilibili 原始文件。不要拿本仓库经过分类的文件反推上游路径。
- ppmina 的 `release`，对比 `release_commit` 下 `ruleset/direct.txt`、`proxy.txt`、`reject.txt`、`apple.txt`、`icloud.txt`、`telegramcidr.txt`。`master` 是生成器源码分支，不能用它的 SHA 代替已发布规则基线。
- 两者的许可证文本；ppmina 的许可证按源码分支 SHA 获取，发布内容仍按 release SHA 获取。

即使分支 SHA 没变，也验证锁定内容并生成清单。sve1r 已有逐文件 SHA256 时，任何基线哈希不一致均令检查失败。ppmina 当前基线仅固定完整 release SHA：脚本记录实取文件哈希，不冒充已存在逐文件锁定校验。源文件 404、下载失败或许可证读取失败均产生不完整报告和非零退出码，不能报告为“没有变化”。

## 2. 审查变化，分别决定接受、拒绝或待查

读 `report.md` 和 `report.json`。`<来源>/diffs/` 保留全部新增/删除规则，不只是样例；`baseline/`、`latest/` 保留原文及 `*.inventory.json`。比较规范化类型、域名大小写、内置策略大小写，保留自定义策略、选项和用户代理大小写。策略变化是旧规则删除加新规则增加；规则顺序变化及重复数量另列。无法识别的行原样保留并标记异常，不能静默忽略。

对每组变化记录：上游完整 SHA、文件/行、所属服务、证据、拟采用的本地类别和原因。建议保存一份可提交的简短维护记录，分为已采用、明确不采用、仍待查三类。上游删除可能是过期或分类调整，也可能误删；新增也可能误归类，不能原样自动接受。

重点审查：

- **服务与域名归属**：优先服务官方网络文档、官方页面及经授权的实际请求日志。域名含 `openai`、`hsbc` 或 `google` 字样并不能证明归属。第三方 CDN/WAF/验证码尽量使用有证据的精确主机，避免整体接管 `amazonaws.com`、`cloudflare.com`、`azureedge.net`、`sentry.io` 等共享后缀。
- **单一类别归属**：保持服务、地区、媒体、游戏分类一致。已归给 OpenAI、HSBC、Apple、Microsoft 等专用类别的目标不应重新出现在 Global、ForeignMedia 等通用类别。补充 HTTPS 登录、WAF、WebSocket、资源和语音依赖时，也检查其他服务是否共用。
- **隔离项**：重读 `docs/quarantine.json` 的原因，不因上游再次出现就恢复旧的广告追踪、拼写错误、非法行或宽泛关键词。若新证据支持恢复，连同隔离记录和回归用例一并修改。
- **许可证**：sve1r MIT 来源保留归属和许可。ppmina GPL-3.0 及其数据来源需单独审查复制范围与许可义务；此仓库当前是“审查但未导入”。大规模复制前明确出处和适用许可，不把 GPL 内容改个名字当作自有规则。检查结果可作为人工核实域名的线索；许可证检查结果不能由“已下载”替代。
- **量级变化**：几万条 direct/proxy/reject 是分类方案候选，不适合追加到已有通用集。比较覆盖缺口与冲突，再选择少量有证据的条目；如果确实要替换分类体系，作为独立设计变更完成迁移与回归。

## 3. 修改自维护类别并验证 Quantumult X 语义

只改采纳变更涉及的本地列表、分类/隔离文档、服务覆盖测试和必要配置。不要复制整个上游仓库，不引入会员解锁、响应篡改或任意重写脚本。

必须考虑这些运行语义：

- `force-policy=服务组` 会覆盖列表内策略，但仍受该组当前选项影响；`static` 第一候选不代表用户当前选择。
- 开启“分流匹配优化”时，host 相关规则偏向精度，相同精度再按加载顺序；“放在前面”不能消除所有冲突。本地优先和 inserted-resource 也是独立设置。维护消除重叠的分类比依赖顺序更稳定。
- `direct` 仍经过 QX；`dns_exclusion_list` 只影响 Fake-IP；MITM、重写、HTTP 抓取额外主机、IPv6、UDP 支持分别检查。不要为了“修复代理”批量增加 DNS 排除、共享 CDN 或默认路由。
- 纯 IP、动态语音端点、应用自带 DNS 以及其他应用共用的基础设施，不能仅靠静态主机清单声称完全覆盖。服务器测速结果也不等于服务登录可用。

运行：

```sh
python3 scripts/build_config.py --mode remote --output Config/quantumult-x.conf
python3 scripts/validate_rules.py
python3 -m unittest discover -s tests -v
```

更改 `Config/base.conf` 或 `Config/categories.json` 后，必须重新构建公开配置，检查 `Config/quantumult-x.conf` 与模板及分类映射一致。公开构建不得使用 `--private-from`；需要私有导入配置时单独生成到仓库外，保持订阅和节点凭证私密。

验证新增规则的实际归属和至少一个不应受影响的邻近域名/共享服务。规则解析器测试、服务覆盖测试、分类唯一性测试须随必要行为变化更新；不要仅修改期望让错误通过。脚本的静态检查不模拟 QX 全部精度匹配、DNS、系统设置或服务可访问性。需要设备验证时先确认用户授权，并报告静态验证与设备验证的边界。

## 4. 最后更新基线并交付

`upstream-lock.json` 是已审核参考输入的历史基线。检查脚本不会自动推进它。只有本次新增/删除/排序变化已经逐类处理、决定记录完整且采纳项验证通过后，才人工更新对应完整 SHA、日期和所有对应参考文件哈希。未采用条目须记录明确理由；仍待查的变化不得通过推进基线藏掉。若只采纳部分而未处理剩余差异，保留旧基线或增加清晰的逐文件审核记录，保证下次仍会看到未解决变化。

注意：锁文件哈希描述**上游原始参考文件**，不是经过本地重新分类后的输出文件。ppmina 仅完成下载/比较时保持 `reviewed-not-imported`；实际采纳须同步来源及许可证说明。

最后审查 `git diff --check`、差异及文件列表，保证 `work/`、私有订阅、节点口令、CA、抓包内容未进入提交。按授权提交或创建可审阅 PR，并报告：哪些分类变化、哪些上游变化未采用、验证结果、是否已推送，以及尚未导入 QX 的事实。若用户要求发布，发布后回读实际 raw URL；推送仓库成功并不代表设备已同步或应用访问已验证。
