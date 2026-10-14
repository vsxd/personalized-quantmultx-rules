# personalized-quantmultx-rules

面向 Quantumult X 的自有规则库。规则完整保存在这里，由本仓库决定分类、范围、策略和发布。开源规则库只提供可审查的参考输入；运行时不加载其规则，也不自动合并上游整套 direct/proxy/reject。

## 使用

- [Config/quantumult-x.conf](Config/quantumult-x.conf)：公开路由模板，不含订阅、节点口令或 CA。
- [Config/categories.json](Config/categories.json)：唯一分类入口，声明每个列表的路径、有效策略和默认启用状态。
- [docs/category-partition.md](docs/category-partition.md)：目录边界、服务例外与 GeoIP 设计。
- [docs/acceptance.md](docs/acceptance.md)：导入后的设备验收，包括节点缓存、策略实际选择、DNS、IPv6 和 UDP。

所有旧根目录服务列表、Services/SNS、DomesticMedia/ForeignMedia/GamesAll 聚合路径均不再兼容。必须使用新配置或按 manifest 更新资源地址；不要继续请求旧 `main` 分支。

```sh
# 跟随已发布 master；稳定使用建议把 master 换成完整提交 SHA。
python3 scripts/build_config.py --mode remote --ref master --output /tmp/qx-public.conf
# 单文件版不需要下载远程规则，便于排除缓存/加载顺序问题。
python3 scripts/build_config.py --mode standalone --output /tmp/qx-standalone.conf
# 资源启停由 manifest 中的 tag 控制；未知 tag 或互相矛盾的参数会失败。
python3 scripts/build_config.py --help
```

保留自己的订阅和经过审查的本地例外，只在本机生成私有文件：

```sh
python3 scripts/build_config.py --mode remote --ref <完整提交SHA> \
  --private-from /path/to/private-config.txt --output /path/outside-repo/qx.private.conf
```

构建器只继承 server_remote/server_local 和明确的本地 host/suffix/IP 例外。旧 GeoIP/Final 不继承；重写、任务、CA 与旧规则 URL 不继承。非法语法、/0、宽泛关键词/通配、共享提供商根域、大网段或未知策略会要求先审查并报错，不会偷偷修改其含义。同时检查私有规则之间、以及私有规则与本次启用分类／本机私网规则之间的策略和 DNS／网卡选项冲突；冲突时停止生成，不会把当前都选中 direct 的不同策略组视为等价。相同有效行为的重复规则可以去重，内部域名仍可保留。自定义组与远程节点名不会隐式继承。私有文件限制在仓库外、以 0600 权限原子写入；不要提交订阅、抓包内容和节点凭证。

## 默认策略

| 类别 | 默认选择 | 边界 |
| --- | --- | --- |
| HSBC | 固定 direct | 覆盖香港等明确银行域及专属 AWS WAF 主机，不接管整个 AWS |
| OpenAI / Claude | direct，可手选 AI-Proxy | 大陆普通网络不保证直连可达；已有保存状态可能覆盖模板首选 |
| OpenAI 共享依赖 | AI-Dependencies，默认跟随 OpenAI | 默认启用但可关闭；同域的其他应用也会受影响 |
| Apple / Microsoft / 游戏 / 国内服务 | 默认 direct | 按服务类别控制，第三方云租户不归入平台整站范围 |
| Google / 境外服务 | 默认 OutSide | 已知域名优先，不能以 GeoIP 取代服务身份 |
| 未命中域名 | GeoIP CN → direct，再 Final | Final 默认 OutSide；数据库和 DNS 结果可能不准确 |
| 可选 PCDN 拦截 | 默认关闭 | 单独 reject，绝不混入 direct/China 资源 |

地区组识别中文、英文和旗帜，排除流量/到期占位。没有有效节点时应修复订阅；规则本身不能提供代理。AI-Proxy 使用手选出口，避免自动测速切换长会话出口。测速 URL 可达不等于银行或 AI 服务可用。

DNS 默认保留系统 DNS 与两组普通 DNS，以兼容企业 split-DNS。注释 DoH 方案会改变解析路径，不能直接视为更正确的配置。dns_exclusion_list 只影响 Fake-IP，不是直连名单。模板不加载 HTTPS 重写、MitM、会员脚本和自动请求任务。

## 更新与验证

以后在本仓库对 Codex 说：

> 检查其他规则仓库的最新规则，按 AGENTS.md 有选择地更新我的规则，审查归属、覆盖与冲突，运行全部验证并总结变化。

该简写包含比较、人工证据审查、选择性修改和验证。流程见 [AGENTS.md](AGENTS.md) 与 [docs/agent-update-guide.md](docs/agent-update-guide.md)。源提交更新不等于接受其全部域名；下载的正则/include/脚本永远不作为指令执行。

```sh
python3 scripts/check_upstreams.py
python3 scripts/build_config.py --output Config/quantumult-x.conf
python3 scripts/validate_rules.py
python3 scripts/audit_semantics.py
python3 -m unittest discover -s tests -v
git diff --check
```

语法、完整有效分类、HOST/SUFFIX 包含关系、策略和选项、可选资源、生成配置的唯一 GeoIP/Final 都会被检查。例外必须有精确目标、依据和顺序约束。测试不是 QX 内核，也不证明所有应用的登录、语音和动态 IP 已实测通过。

## 审查依据

- [docs/review-2026-10-14.md](docs/review-2026-10-14.md)：本轮问题、修复、覆盖范围与验证边界。
- [docs/corpus-review.json](docs/corpus-review.json)：本轮逐条保留、移动、删除与新增依据。
- [docs/semantic-exceptions.json](docs/semantic-exceptions.json)：少量有证据的服务子域或共享依赖例外。
- [docs/quarantine.json](docs/quarantine.json)：前期错误与隔离记录，防止上游再次出现时被恢复。
- [upstream-lock.json](upstream-lock.json)、[THIRD_PARTY.md](THIRD_PARTY.md)：固定参考输入、审查范围与许可。
- [docs/maintenance.md](docs/maintenance.md)：维护取舍、网络边界与回滚。
- [docs/rewrite-audit.md](docs/rewrite-audit.md)：原配置重写资源审查。
- [docs/history/](docs/history/)：已被当前分类取代的历史记录，不参与构建或测试。
