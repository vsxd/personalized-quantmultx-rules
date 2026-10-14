# personalized-quantmultx-rules

面向 Quantumult X 的自有规则库。规则完整存放在本仓库，配置只向本仓库加载分流列表。其他开源项目是审查参考源，不是运行时依赖，也不会被定时任务自动覆盖进来。

当前重点：Mac、香港 HSBC、ChatGPT/Codex、Claude、Apple、Microsoft、Google、游戏、国内外媒体和国内/全球兜底。服务专属域名、共享依赖、通用区域与可选拦截分开维护。域名库无法承诺覆盖未来出现的全部服务，也不能替代设备日志、DNS 和节点验证。

## 使用

- [Config/quantumult-x.conf](Config/quantumult-x.conf)：公开的纯路由模板，无订阅凭证或 CA 私钥。配置里的 `master` 表示本仓库已发布版本；在 PR 尚未合并时，先用构建器指定该 PR 的完整提交 SHA。
- [Config/categories.json](Config/categories.json)：本仓库唯一的配置加载顺序和有效策略映射。
- [Rules/Services/](Rules/Services/)：服务规则；OpenAI 的共享供应商单独位于 `OpenAI-Dependencies.list`。
- [Rules/Region/](Rules/Region/)、[Rules/Media/](Rules/Media/)、[Rules/Games/](Rules/Games/)：自行整理的通用分类。
- [Rules/Optional/BilibiliPCDNReject.list](Rules/Optional/BilibiliPCDNReject.list)：可选 PCDN 拦截，默认未加载，启用时必须单独使用 `force-policy=reject`。

完整配置可从仓库生成。固定到 commit 可以避免远程分支漂移；单文件版可排除远程规则更新/缓存因素：

```sh
python3 scripts/build_config.py --mode remote --ref <完整提交SHA> --output /tmp/qx-reviewed.conf
python3 scripts/build_config.py --mode standalone --output /tmp/qx-standalone.conf
```

需要保留自己的订阅和本地例外时，只在本机生成私有文件：

```sh
python3 scripts/build_config.py --mode remote --ref <完整提交SHA> \
  --private-from /path/to/private-config.txt --output /path/outside-repo/qx.private.conf
```

构建器只继承服务器订阅/节点和非 `final/geoip` 本地例外，不继承重写、任务、CA 或旧规则 URL。导入本地例外时拒绝非法语法、/0 和未知策略组；原自定义组与远程节点名不会隐式继承。私有输出权限为 `0600`，拒绝写入本仓库。不要把订阅、日志完整 URL、节点凭证和 P12 提交到 Git。

## 默认路由选择

| 类别 | 模板行为 | 注意 |
|---|---|---|
| HSBC | 强制 `direct` | 包括已验证的专属 `hsbc.edge.sdk.awswaf.com`；不把整个 AWS/CDN 直连 |
| OpenAI / Claude | 手选 `direct` 或 `AI-Proxy` | 保留用户的直连选择；大陆普通网络直连可达性不作保证 |
| AI-Dependencies | 默认跟随 OpenAI，可独立切换 | Cloudflare challenge、WorkOS、Stripe、Intercom 等被其他应用共享 |
| AI-Proxy | 美国/新加坡/日本的手选节点 | 避免自动测速导致长会话换出口；节点所在地区不代表服务一定接受 |
| Apple / Microsoft / 国内 | 默认直连 | 既有设备保存的手选状态可能覆盖模板首项 |
| Google / Global / Final | 默认 OutSide | `Final` 只在其他域名/IP/GeoIP 规则未覆盖时生效 |

地区组识别中英文和旗帜，并排除流量/到期占位名称。没有节点时必须修复订阅或手动选可用节点，规则库不能凭空提供代理。`server_check_url` 测速只代表测试 URL 可达，不证明银行/AI 登录、WebSocket 或 UDP 可用。

模板保留两组普通 DNS 与系统 DNS 以兼容企业 split-DNS，并提供注释 DoH 方案。`dns_exclusion_list` 仅控制 Fake-IP；DoH 只保护到解析器的传输，也不保证解析器返回未过滤结果。HTTPS 重写、会员脚本、MITM 和流媒体查询均不进入默认配置。

## 更新与验证

以后在这个仓库打开 Codex，直接说：

> 检查其他规则仓库的最新规则，按 AGENTS.md 更新我的规则库；重点审查新增/删除域名、归属与冲突，运行全部验证并总结变化。

具体流程见 [AGENTS.md](AGENTS.md) 和 [docs/agent-update-guide.md](docs/agent-update-guide.md)。检查脚本生成差异报告，agent 根据证据逐项接受/拒绝；不会机械合并整套 direct/proxy/reject。

```sh
python3 scripts/check_upstreams.py
python3 -m unittest discover -s tests -v
python3 scripts/validate_rules.py
python3 scripts/build_config.py --output Config/quantumult-x.conf
git diff --check
```

“零语法错误”不等于设备实测通过。宽泛 keyword、共享服务、旧 IP 段、DNS 选项会继续显式报告。每次更新都必须审查新增告警、运行路由案例，并按 [docs/acceptance.md](docs/acceptance.md) 验证真正的策略路径。

## 维护依据

- [docs/maintenance.md](docs/maintenance.md)：分类原则、DNS/策略边界与来源选择。
- [docs/category-partition.md](docs/category-partition.md)：分类归属整理和保留的条件重叠。
- [docs/quarantine.json](docs/quarantine.json)：被移除或隔离的旧规则与原因。
- [docs/rewrite-audit.md](docs/rewrite-audit.md)：原配置远程重写与依赖审查。
- [upstream-lock.json](upstream-lock.json)：审查参考源的固定提交和输入哈希。
- [THIRD_PARTY.md](THIRD_PARTY.md)、[LICENSES/](LICENSES/)：来源与许可。参考上游再整理不消除原始许可要求。

本次重构不保留仓库根目录旧 `OpenAI.list` / `Claude.list` / `HSBC.list` 路径。必须迁移到新配置后使用，不要仅更新旧订阅。
