# 分类与兜底设计

`Config/categories.json` 是唯一活动分类清单。每个规则文本只在一个源文件中维护；默认启用、可选启用和有效 force-policy 由同一份 manifest 决定。文档中的分类不是第二套装载顺序。

| 目录 | 内容 | 不属于这里的内容 |
| --- | --- | --- |
| AI | OpenAI、Claude 等服务自有域名和专属租户 | 通用云供应商、开发工具下载站 |
| Banking | HSBC 明确银行业务及专属风控主机 | 全 AWS、通用统计/标签 CDN |
| Platforms | Apple、Microsoft、Google 等通用产品服务 | 已单独归属的游戏、媒体、社交；任意云租户 |
| Messaging / Social | 通讯与社交服务 | 新闻、流媒体和通用遥测 |
| Developer | 代码托管、开发工具、包仓库 | 所有含 github 字样的域名 |
| Games | 明确游戏平台/游戏服务 | Sony/Microsoft 整家公司及共享 Unity 根域 |
| Media | 视频、音乐、新闻、媒体集团、社区等用途 | 聊天工具、历史云 IP 池 |
| Regional | 剩余明确的国内与境外服务域名 | 国家顶级后缀、GeoIP、ASN、Final |
| IP | 有当期官方依据、确需裸 IP 的应用地址 | 过期媒体、整段共享 CDN/云网络 |
| Optional | 共享 OpenAI 依赖、独立 PCDN 拦截 | 把拒绝策略强制改成直连的混合列表 |

地区和默认策略是属性，不是域名所有权证据。一个厂商的不同产品可以分别属于游戏、聊天或媒体分类；收购关系不能证明所有 CDN 都是该产品专属。

## 范围原则

默认域名清单只使用 HOST 和 HOST-SUFFIX。后缀必须有域名边界；不使用 Google/Office 一类任意子串，也不使用 apple.* / onedrive.*。已由同策略父后缀覆盖的子域不重复维护。品牌顶级域名必须能证明当前委派与注册控制，不能与可公开注册的 .cn/.co.in 混为一谈。

共享云根域从 Microsoft/Global/Media 等默认类别移除，不在另一文件里重新接管。服务专属第三方租户尽量使用精确 HOST；真正共享的 WorkOS、Cloudflare challenge、Stripe、Intercom 只能明确记录影响范围。OpenAI 共享依赖可关闭，关闭后的未命中流量自然经过 GeoIP/Final；不为此再放一份 intercom.io 到 ForeignMedia。

少数服务子域需要与父域不同策略，如国际版内容与国内业务、OpenAI 官方依赖 humb.apple.com。例外文件必须绑定精确目标、有效策略、选项和较窄规则在前的约束，并解释依据。不能用例外掩盖非法语法、重复兜底和无边界模式。

## GeoIP 是最后一层地理兜底

配置先表达明确服务域名，保留本机/私网和必要的应用 IP 分类，最后只有：

```text
geoip, cn, direct
final, Final
```

GeoIP 不写进可复用类别，.cn 也不是“服务器在中国”的证明。已知需要指定策略的海外服务不能因为 Final 默认代理就删除：其 DNS 结果可能是中国 IP，或数据库有误，明确域名应先确定意图。反过来，无法证明属于单一应用的共享 CDN/云 IP 不抢在 GeoIP 前捕获。

构建器提供 remote 和 standalone，两种输出使用同一启用清单和有效策略。远程方式默认把常规 China／Global／Game 叶子汇总成 3 个资源，总计只加载 11 项；全新导入若需要排除加载/缓存差异，可先使用 standalone。QX 的匹配优化、优先本地分流和插入资源开关是独立运行设置；静态清单的顺序不等于所有设备状态下的实际执行顺序，验收必须查看命中的规则和完整策略路径。

完整迁移和删除记录见 corpus-review.json。docs/history/ 中第一轮“保留184告警”和条件重复的决策已被本轮取代。

## 远程资源汇总

`Rules/` 是唯一手工维护的规则源；manifest 的 `remote_group` 只声明发布分组，不改变规则归属或策略。构建器生成 `Bundles/China.list`、`Bundles/Global.list`、`Bundles/Game.list`，保留来源注释和许可说明。默认配置的 112 个启用叶子仍全部覆盖，共 2,947 条类别规则；资源数量变为 11 个。

HSBC、OpenAI、Claude、共享 OpenAI 依赖、Apple、Microsoft、Google 和 Telegram IP 保留独立资源。共享 OpenAI 依赖直接使用 OpenAI 策略；它的独立资源只用于明确共享范围与启停，不再需要额外策略组。OpenAI 与 Claude 各自直接提供 direct、美国、新加坡、日本和 proxy 候选。

汇总按 manifest 的成员顺序生成，第一次出现的分组决定远程资源位置。审查检查实际汇总后的有效规则、选项、覆盖数量及窄规则先后；不能只验证源文件。具体包括国际 iQIYI 先于国内父域、humb.apple.com 先于 Apple、启用的 PCDN 子域先于 Bilibili。

如果自定义选择改变一个分组的成员，生成器对该分组退回叶子 URL，不能继续引用包含已禁用条目的默认汇总。需要任意选择但保持单文件时使用 standalone。生成文件不接受手改，先改叶子/manifest，再运行 build_bundles.py 和 build_config.py；CI 检查两种生成结果。

当前完整逐行复审与待核实边界见 [deep-review-2026-10-14.md](deep-review-2026-10-14.md)；源文件共 2,949 条，其中可选 PCDN 的 2 条默认关闭。
