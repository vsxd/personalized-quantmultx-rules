# 自有规则分类与去重记录

这里的规则由个人仓库独立维护。上游提供历史参考与可审查的增量，不是自动镜像源；规则归属、策略、修复及发布都在本仓库决定。源提交与许可保留用于追溯，不能将上游较新的提交直接覆盖本地规则。

必选列表按 `docs/rule-categories.json` 中顺序确定精确规则归属。键是规则类型与目标，不含策略；域名转为小写，User-Agent 保留大小写。相同键只保留在第一个必选分类中。后缀、关键词、IP 范围的包含关系不等同于相同键，需另行审查，不能按名称批量删除。

| 分类文件 | 整理前条数 | 整理后条数 | 移出重复条数 |
|---|---:|---:|---:|
| Rules/Services/Apple.list | 114 | 114 | 0 |
| Rules/Services/Microsoft.list | 412 | 411 | 1 |
| Rules/Services/Google.list | 77 | 77 | 0 |
| Rules/Games/GamesAll.list | 23 | 22 | 1 |
| Rules/Media/DomesticMedia.list | 236 | 236 | 0 |
| Rules/Services/SNS/Discord.list | 6 | 6 | 0 |
| Rules/Media/ForeignMedia.list | 1581 | 1576 | 5 |
| Rules/Region/China.list | 275 | 264 | 11 |
| Rules/Region/Global.list | 634 | 557 | 77 |

总计移除95条重复目标，其中13条为较后Global规则携带的 `force-remote-dns`，早先Google归属没有该标记。本次保留早先分类的策略与选项，不将后置标记搬到另一策略上；详情逐条记录在 `category-partition.json`。这不是删除不支持的语法。其余48条有效位置的该选项保留。

`Rules/Services/OpenAI-Dependencies.list` 是可选资源，不作为必选分类的永久所有者。`intercom.io` 在此列表与 ForeignMedia 中的重复有明确原因：前者开启时可以跟随AI策略，关闭时仍有Global兜底。独立的 BilibiliPCDNReject 也需显式启用，其拒绝意图不并入普通服务分类。

所有通用列表第三列统一为本仓库的 Apple、Microsoft、Google、Game、China 或 Global。消费者仍可通过 force-policy 显式覆盖；列表本身已不依赖历史 Foreign Media、Domestic Media、Microsoft Domestic、Apple Domestic 等上游策略名称。

本记录只证明分类与静态规则一致性；具体设备的匹配优先级、DNS路径、当前策略组选项、IP直连、应用动态地址仍需实机日志验证。

后续定点收敛已记录在 `shared-infrastructure-review.json`：9条共享基础设施规则转到Global，5个Google/Game关键词和1个Apple依赖关键词改为明确后缀，DomesticMedia的5个宽地址段、公共DNS和3个Fake-IP捕获地址移出。原阶段记录的48条DNS选项在进一步去重/去关键词后保留45条。剩余184条警告均按类型和具体位置给出保留理由与限制，其中宽CIDR、关键词、顶级通配仍是显式覆盖范围取舍，不能称为所有权验证通过。
