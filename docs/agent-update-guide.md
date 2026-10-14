# 让 Codex 检查并维护上游更新

本仓库维护自己的服务分类、例外规则和策略边界。以后可以直接说：

> 检查其他规则仓库最新规则，按本仓库的分类和策略要求，有选择地更新我的规则，验证后整理变更。

“检查下别的规则仓库最新规则”等简写包含比较、证据审查、选择性更新本仓库和验证。只有明确说“只检查”“不修改”时才停在报告。提交、推送、PR 和合入按本次用户授权执行，无需重复确认已授权动作。仓库维护不自动导入 Quantumult X、改变当前策略或重连 VPN。

## 1. 保留现场，固定参考输入

先读 `AGENTS.md`、`upstream-lock.json`、`THIRD_PARTY.md`、`Config/categories.json`、`docs/category-partition.md`、`docs/corpus-review.json`、`docs/quarantine.json` 和 `docs/semantic-exceptions.json`。`Config/categories.json` 是当前发布分类的唯一配置清单；`docs/history/` 只是旧审查记录。执行 `git status --short`，保留已有修改，不使用 reset 或全目录覆盖。核对 `master` 仍为发布分支，不根据上游分支名更改订阅地址。

使用 Python 3.10+、git；安装并登录 `gh` 后可使用其 GitHub API 配额：

```sh
python3 scripts/check_upstreams.py
python3 scripts/check_upstreams.py --source blackmatrix7
python3 scripts/check_upstreams.py --source v2fly
```

脚本从锁文件发现全部来源，不限于某两个仓库。`git ls-remote` 解析最新分支 SHA，原文下载使用完整 SHA。**Git 树目录发现会调用 GitHub API**：可用时使用 `gh api`；未安装 gh 时使用匿名 API，配额较低。API 限流、认证失败、网络错误、树被截断都是真实检查失败，不是“没有更新”。可用 `gh api rate_limit` 查看剩余额度；不要输出认证令牌。

报告、原始参考文件和清单位于忽略目录 `work/upstream-check/<UTC时间戳>/`。检查器不改本地规则、配置或锁文件，不执行远程脚本。锁定的文件与许可证 SHA256 均校验；404、哈希不一致、目录或依赖不完整产生非零退出码和 INCOMPLETE 报告；所有比较完成但原始条目存在语法问题则报告 REVIEW_REQUIRED，同样非零退出。后者与本仓库规则测试失败是两回事，不能为了返回 0 而豁免源文件缺陷。

## 2. 七类参考来源与原生格式

| 来源 | 检查内容 | 使用边界 |
| --- | --- | --- |
| sve1r | `develop` 的历史真实路径及 Bilibili `repair_reference`；`Rules` 目录发现 | MIT 历史素材，保留本地修正和服务边界。 |
| ppmina | `release` 的六个生成规则文件；`master` 的许可证 | GPL-3.0，比较但不复制整个 direct/proxy/reject 分类。 |
| blackmatrix7 | QX **及 Surge** 的选定 AI、平台、通讯、游戏、媒体服务列表；两个格式目录发现 | GPL-2.0，交叉核实服务划分和覆盖，不能默认采纳宽泛匹配。 |
| SukkaW | `Source/domainset`、`Source/non_ip`、`Source/ip` 及选定内容 | AGPL-3.0，参考域名/IP 分离、下载与服务区分；保持 DOMAIN-SET 原生语义。 |
| v2fly | 选定服务、地区及游戏/媒体分类；`data` 目录发现；所有可达 include 依赖 | MIT，显式域名按归属选择采纳；include、属性、正则仍是待审查证据。 |
| ACL4SSR | Clash 的平台、AI、通讯、开发者等选定列表和目录发现 | CC-BY-SA-4.0，README 页脚是许可声明；格式按兼容的 Surge 风格规则清单检查，不能称为 QX 文件。 |
| Loyalsoldier | `release` 的 DOMAIN-SET、RULE-SET、CIDR；`master` 许可证 | GPL-3.0，比较大型地区集与生成语义，不批量并入。 |

`rule_branch`/`rule_commit` 指定生成规则，`license_branch`/`license_commit` 独立指定许可证来源；不要用生成器的提交替代 release。`license_path` 可指向 README 等真实许可声明。`files` 或 `reference_files` 每项可声明 `format` 与原文 SHA256。空文件清单必须有实际目录检查范围，或显式说明仅作背景参考；不能让空范围报告为规则已全面检查。

格式必须保持区别：QX 的 `host-suffix` 与 Surge 的 `DOMAIN-SUFFIX` 不自动互换；Surge DOMAIN-SET 的 `.example.com` 包含后代，而 `example.com` 仅精确主机。v2fly 的 `include:x @cn` 是筛选依赖，`@-!cn` 是排除名为 `!cn` 的属性，不能当作所有子规则增加一个标签。正则、include 文件名大小写与属性保留，不把 v2fly、Surge 的表达式直接写进 QX。比如 ppmina 的 Telegram 参考文件出现 Surge 风格 `IP-CIDR6`，不能静默改名为 QX `ip6-cidr` 后宣称原文件有效；原始问题必须仍在报告里。

## 3. 检查显式文件、目录及间接依赖

读 `report.md` 和 `report.json`。`<来源>/diffs/` 包含选定文件全部新增/删除条目；`baseline/`、`latest/` 保留原文及 `*.inventory.json`。策略、选项、顺序和重复变化均可见；未知行保留原文并标记异常。COMPLETE 只代表配置的参考比较完成，不代表差异已接受、服务可访问或所有外部仓库均已覆盖。

`tree-diff.json` 列出检查子树中新建、删除和修改的路径，发现新增服务分类。**目录发现没有逐个审阅其中所有文件内容**：对相关的新文件固定 SHA 后下载并评审，必要时加入锁文件选定清单。目录太大导致截断时缩小 `inventory_paths`，不能接受部分树当完整结果。

v2fly 另使用完整 SHA 的有界源码归档，读取 `data/` 中的普通文件，避免逐一请求上千个依赖；不会执行或解压任意路径/链接。`dependencies/baseline.json`、`latest.json` 记录选定根文件的完整可达 include 图、原文哈希、原生条目和属性；`dependencies/diff.json` 与 `dependencies/diffs/` 揭示父文件不变但间接子文件变化的情况。缺失依赖、循环、未知语法均令检查不完整。这个图用于**发现和审阅**，不应用属性过滤，不自动生成或导入规则。需要采用依赖中的域名时，必须单独决定服务边界。

最新逐行审查与未决项见 `docs/deep-review-2026-10-14.md` / `.json`，下次更新应复核其中的待核实范围。`upstream-lock.json` 现将 LINE、Docker、Python、npm、Notion 列为显式比较文件，不能只看旧聚合列表。

本轮维护决定见 `docs/upstream-review-2026-10-14.json`：它保留源文件缺陷、未采纳的最新变化和真实比较范围；原始下载与完整差异仍留在忽略的 `work/`。

对每组变化记录来源完整 SHA、文件/行、归属、证据、采用类别以及理由，分为已采用、明确拒绝、仍待查。上游删除可能是过期、改分类或误删；新增也可能是共享基础设施，均不能自动接受。

## 4. 审查规则边界与冲突

- 服务归属以官方网络文档、官方页面及授权范围内的实际请求为先。名字带品牌不证明归属。认证、WAF、验证码、WebSocket、资源、语音依赖需分清第一方、专属租户和共享平台，避免接管整个 `amazonaws.com`、`azureedge.net`、`sentry.io` 等。
- 每个服务有一个明确叶子文件；使用场景不同可细分，不能把通讯、新闻、社交塞进海外媒体。平台公司和所属独立服务分开，例如开发者/GitHub、游戏/Xbox、视频/YouTube。现有策略名由配置映射决定，不从文件夹名字推断最终出口。
- 当前默认域名清单只使用精确主机和有边界的后缀。拒绝笼统关键词、品牌通配符、国家 TLD 兜底和 User-Agent 猜测。不为消除审查失败加大范围例外。
- 共享 CDN/云 IP 会承载无关租户；动态 DNS 解析结果不能当永久服务 IP。只有当前官方材料确实要求的 IP 路由才独立放入 IP 清单，记录出处、日期和复核要求。仅在配置末尾保留一个 `geoip, cn, direct`，之后 `final`；服务子列表不得自带 GeoIP/Final。
- `data/domain-boundaries/` 的 IANA 与 PSL 快照检验已委派 TLD、注册/共享租户边界。PSL PRIVATE 后缀不是该供应商应用全体域名。更新这份数据时连同来源、许可和哈希核对；不能只改哈希掩盖错误。
- 重读隔离记录和语义例外；上游再次出现不构成恢复理由。`docs/semantic-exceptions.json` 只记录精确目标/策略对和必要原因；对默认关闭的可选列表同样审查。地区兜底、正反域名和服务依赖一起验证。
- MIT 衍生条目保留许可与归属；GPL、AGPL、CC-BY-SA 参考源当前没有批量导入。未来复制须单独处理许可，不能把其内容改名当 MIT。许可证已下载不代表已履行所有复制义务。

## 5. 验证并交付

修改涉及的叶子清单、分类清单、覆盖/隔离证据和测试。`Bundles/` 是 manifest 的 remote_group 自动汇总输出，不能作为第二套手工维护的源；先重新生成汇总，再生成配置。不可引入会员解锁、响应篡改或任意远程重写脚本。运行：

```sh
python3 scripts/build_bundles.py
python3 scripts/build_config.py --mode remote --output Config/quantumult-x.conf
python3 scripts/validate_rules.py
python3 scripts/audit_semantics.py
python3 -m unittest discover -s tests -v
git diff --check
```

验证每项采纳的正例，以及不应受影响的邻近域名、共享租户或 IP。语义审查包括父子后缀、精确主机重叠、选项/策略以及 CIDR 交集；不可通过批量豁免或只改测试期望消除错误。更新 `Config/categories.json` 或 `Config/base.conf` 后重新生成配置。公开构建不带 `--private-from`；私有配置输出到仓库外。

QX 开启匹配优化时偏向精确规则，同精度再受顺序和加载方式影响；单靠“放前面”不能解决冲突。`force-policy=服务组` 仍受该组当前选择影响，只有字面的 `direct` 才固定直连策略。DNS/Fake-IP、系统代理、IPv6、UDP、MITM、重写及应用自带解析各有运行边界，静态清单不能证明所有动态端点可访问。设备验证按已有用户授权执行，并清楚区分静态通过与真实应用通过。

锁文件是已审核参考输入的基线。只有相关新增、删除、顺序和依赖变化已处理、拒绝理由记录完整、采纳项验证通过，才人工更新对应 SHA、日期与哈希。若有未解决差异，保留旧基线或清楚的逐文件审核状态，确保下次仍能看到；检查器不会自动推进。报告中应列出检查范围和仍未采用的变化。

最后检查差异、公开机密扫描、生成配置一致性和完整测试，保证 `work/`、订阅凭证、CA、请求内容不提交。按用户授权提交、更新 PR 或合入；发布后回读真实 raw URL。分支推送、master 合入、设备同步和应用访问成功是不同事实，分别报告。
