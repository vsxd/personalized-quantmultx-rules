# 第二轮逐行审查：已启用资源与完整源规则库

本轮从 `5e42737a28ccf006408b9be9b513fdd50f4a7b4b` 开始，逐行阅读全部 **113 个源文件、2,902 条原规则**，并校验实际默认加载的 **11 个资源**。修正 23 个叶子文件，最终共 **2,949 条规则**，其中 **2,947 条默认启用**；另 2 条 PCDN 拦截保持默认关闭。

主要问题是服务入口／依赖遗漏、专属第三方主机写成后缀匹配，以及旧媒体分类混入其他产品。此次没有更改配置模板、策略组、图标、DNS、订阅项数量或 QX 端侧设置。源文件修改通过构建器更新三个 Bundles。

逐文件前后 SHA-256、数量、精确新增／删除行、官方请求证据、未采纳项见 [机器可读审查记录](deep-review-2026-10-14.json)。早期的 [corpus-review.json](corpus-review.json) 保留首次迁移记录，通过 follow_up_changes 指向本轮，不能把旧记录当作当前分类。

## 当前 11 个资源逐项结论

| 实际发布资源 | 当前规则数 | 本轮结论 |
| --- | ---: | --- |
| `Rules/Banking/HSBC.list` | 11 | 保留固定 direct 与精确 HSBC WAF 主机；未扩到整个 AWS WAF 或通用 CDN。 |
| `Rules/AI/OpenAI.list` | 18 | 保留现有核心域及专属租户边界。官方帮助页本轮 HTTP 403，未宣称重新核验了最新官方清单。 |
| `Rules/AI/Claude.list` | 6 | 与本轮可获取的官方网络文档交叉核对；未把通用包仓库、Google Storage 或遥测归为 Claude 专用。 |
| `Rules/Optional/OpenAI-SharedDependencies.list` | 13 | 保留用户已接受的共享依赖范围与独立启停；同一主机上的其他应用仍可能受该策略影响。 |
| `Bundles/Global.list` | 1,824 | 核对所有成员叶子及实际拼接顺序；补齐 LINE、Docker／Python／npm、Notion、部分流媒体及资源入口，修正产品分类。 |
| `Bundles/China.list` | 342 | 补虎嗅主域、荔枝音频／播客；软件商城 lizhi.io 移到国内通用规则，保持 China。 |
| `Bundles/Game.list` | 166 | 补 Minecraft 现代服务 API；保持既定游戏策略及已审查范围。 |
| `Rules/Platforms/Apple.list` | 70 | 补 6 个官方目标，涉及 Universal Links、Apple DNS 和专属中继／管理内容服务。 |
| `Rules/Platforms/Google.list` | 278 | 补 6 个精确 OAuth、Gemini API 与 Code Assist 主机。 |
| `Rules/Platforms/Microsoft.list` | 205 | 补 3 个 M365 产品后缀和 5 个精确认证／目录主机。 |
| `Rules/IP/Telegram.list` | 14 | 与当前官方 CIDR 文件逐条及 SHA-256 一致；保持官方范围。 |

## 已修复的问题

### 1. 服务组存在，但入口或依赖未被该组覆盖

- **Microsoft 365**：补 `cloud.microsoft`、`static.microsoft`、`usercontent.microsoft`，以及 `login.windows.net` 等 5 个官方认证／目录主机。没有恢复整个 `windows.net`、Azure 租户根域或 `.microsoft` 顶级域。
- **Google**：补 `oauth2.googleapis.com`、`openidconnect.googleapis.com`、`generativelanguage.googleapis.com`、`cloudaicompanion.googleapis.com`、`cloudcode-pa.googleapis.com`、`ai.google.dev`，全部为 HOST。保留对通用 `googleapis.com` 和存储根域的排除。
- **Apple**：补 `apple-dns.net` 后缀及 5 个官方精确主机，包括 `app-site-association.networking.apple`、`apple-relay.cloudflare.com`、`apple-relay.fastly-edge.com`。没有接管 Cloudflare／Fastly 其他客户。
- **LINE**：原文件仅有两个 CDN 后缀；补主入口、消息服务、短链及 LINE 专属 Naver 子域，不接管整个 `naver.jp` 或 LINE 游戏／零售业务。
- **开发工具**：补 Docker Registry、npm Registry、PyPI 及实际包下载主机。`files.pythonhosted.org` 和 Docker 专属 S3 主机使用精确匹配；未添加全 S3、Cloudflare R2、Auth0、Bugsnag。
- **媒体与游戏**：补 MyDisney 身份服务、HBO Max 入口／API／图片、ABEMA 当前图片源、Bilibili 国际版封面主机、Twitch 扩展、Minecraft 服务 API，以及虎嗅／荔枝缺失主域。
- **Notion**：补官网现用 `notion.com` 和状态页；页面引用的共享 Contentful 资源不整域收录。

这些明确服务仍应放在 GeoIP 前面。即使 Final 默认也走代理，依赖只有地理兜底时仍可能因为解析到中国 IP、GeoIP 差异或策略切换而与主请求走不同路径。

### 2. 收窄 14 条第三方／供应商规则

`bucketeer.jp` 是通用功能开关平台，不能整个归入 ABEMA；改为官网当前使用的 `api-abematv.bucketeer.jp` 精确主机。

另 13 条媒体 CDN／遥测端点依据不可变 MIT 输入的 `full:` 原生语义，由 HOST-SUFFIX 改为 HOST。保留真实端点，排除未经证明的后代主机。例如 `disney.my.sentry.io`、`foxnewsplayer-a.akamaihd.net` 和服务专属 `omtrdc.net` 主机。没有通过扩大语义例外来掩盖问题。

### 3. 修正分类，保留原有效策略

| 目标 | 修正后的归属 | 路由变化 |
| --- | --- | --- |
| `foxcredit.com` / `foxcredit.org` | GlobalDomains：信用合作社，不是 Fox 视频 | 仍 Global |
| `lizhi.io` | ChinaDomains：软件商城，不是荔枝音频 | 仍 China |
| Ameba 博客、漫画及 Ownd 的 4 个域名 | Social/Communities | 仍 Global |
| `winticket.jp` | GlobalDomains：独立业务，不是 ABEMA 视频 | 仍 Global |
| `twitteroauth.com` | Developer/Tools：独立 PHP 库 | 仍 Global |
| `polygon.com` | Technology 新闻；官方说明已被 Valnet 收购 | 仍 Global |
| `fxnetwork.com` / `fxnetworks.com` | Disney | 仍 Global |

## 冲突、过度覆盖与 GeoIP

- 所有规则源只保留 HOST／HOST-SUFFIX，必要的 Telegram IP 单独维护；没有新增关键词、User-Agent、国家顶级后缀、全云网段或应用快照 IP。
- 校验整个默认拼接结果及可选资源，包含重复目标、父子后缀、精确主机、策略／选项不一致、CIDR 交集、汇总顺序和覆盖数量。**没有未解释的静态错误，也没有新增语义例外。**
- 现有 26 个已接受的语义发现继续受精确规则、策略、选项和顺序约束；不能把这个数字表述成“完全没有任何重叠”。其来源包括 Telegram 官方大网段、明确共享依赖以及 iQIYI／humb.apple.com 等窄范围覆盖。
- Telegram 官方当前清单不含其他上游仍有的 `95.161.64.0/20`、`109.239.140.0/24` 或整段 `91.108.0.0/16`，不为增加数量而重新引入。
- 兜底仍只在配置末尾出现一次 `geoip, cn, direct`，随后 `final, Final`；所有服务文件和 Bundles 都不含地理／最终兜底。
- 不认识的目标交给 GeoIP／Final；已知服务保留明确规则。使用场景是目的地址分流，同一个共享域名不能仅凭规则区分“哪个应用发出的请求”。

## 上游最新状态和来源边界

重新检查 sve1r、ppmina、blackmatrix7 的 QX 与 Surge、SukkaW、v2fly、ACL4SSR、Loyalsoldier。完整检查记录为 `20261014T095242.216064Z`；为本轮采纳的 LINE、Docker、Python、npm、Notion 额外扩展 5 个显式 MIT 文件，复核记录为 `20261014T100702.859418Z`。共 **130 个选定参考文件**，另有目录变化及 v2fly include 闭包检查；不声称逐域名核验了这些外部仓库的全部内容。

与上一轮相比，选定来源的版本基本相同。SukkaW 中此前未采纳的单个通用 CDN 图片主机变化仍保持可见。没有推进来源提交基线，也没有整套导入 GPL／AGPL／CC-BY-SA 清单。

完整上游检查保持 `REVIEW_REQUIRED`：sve1r 原文 2 条 CIDR 格式错误、ppmina 原文 4 条非 QX IPv6 类型错误仍存在。这不代表本地规则失败，也不通过静默修正原文来伪造来源检查通过。扩展的 v2fly 检查为 `COMPLETE`。

## 尚不能下结论的地方

- 完整逐行静态审查 **不等于** 对每个历史域名重新核实当前注册人、所有业务和全部动态依赖。尤其 Fox 的地区／活动域名、Global 的旧站点、Qobuz 的品牌变体，保留明确后缀不代表它们都重新通过了当前权属证明。
- `us.to` 的共享动态域名范围仍待独立权属核验；本轮 FreeDNS 官方查询在当前网络失败，未伪称获得成功证据，也未仅凭名称或网络失败删除规则。
- SonyMedia 仍只有旧专属 CDN 主机。Sony 官网相关页面本轮 403，SonyLIV 超时，指定 MIT 快照中也未取得对应独立条目；记录为覆盖待核实项。失败不证明域名无效。
- OpenAI 官方帮助页本轮 403，保留已有已审查清单。当前 Claude 官方网络文档与 Telegram 官方 CIDR 可获取；两者的验证状态分别记录。
- QX 的匹配优化、资源缓存、已保存策略、DNS／Fake-IP、UDP 和 GeoIP 数据库有独立运行状态。本轮只修改仓库，没有修改端侧或把静态测试结果当作应用实测。

## 验证与维护

三个 Bundles 和公开配置均重新生成。语法检查为 **0 错误、10 个既有提示**；语义检查只有 **26 个既有已接受项**。新增 **15 项回归测试**，全套 **130 项通过**，`git diff --check` 通过。

以后更新需同时读取本报告和机器记录中的待核实项；上游再次出现宽规则不构成恢复理由。具体维护命令及许可边界见 [agent-update-guide.md](agent-update-guide.md)。
