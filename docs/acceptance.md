# 导入与设备验收

1. 保存 QX 当前配置、策略选择截图和可用节点。新配置不继承旧重写/CA；不要把私有备份提交到 Git。
2. 先导入固定 SHA 的新配置或 standalone 单文件版。模板不是“仅更新原来几个 URL”；根目录旧服务列表已取消。
3. 核对节点订阅与地区组非空。订阅返回 200 不代表有效；必须能解析为真实节点。已失效的订阅若仍有可用缓存，先导出/备份缓存，不要直接清掉。切换整个配置可能丢掉只存在于缓存的节点。
4. 关闭 QX UI 的 HTTP 抓取与 MitM。只删除文件中的证书/hostname 不足以证明全局捕获已经关闭。不要替银行/App 绕过证书校验。
5. 核对实际策略：HSBC 资源固定 direct；分别核对 OpenAI、Claude 的预期出口；共享 OpenAI 依赖直接使用 OpenAI 策略。本次移除了 AI-Proxy 和 AI-Dependencies 中间组，导入后重新选择 OpenAI／Claude 的有效候选，避免保存状态仍引用旧组。已有组可能保留上次选择；配置候选第一项不证明已切换。
6. 核对分流匹配优化、优先本地规则、插入资源状态。先保持优化开启，按日志检查精确规则；对变化重连 QX/重启相应 App，避免旧连接继续使用原出口。
7. 查看网络活动，仅记录域名、类型、命中规则、策略完整路径、时间与 `mitm_is_on`，不收集请求正文、Cookie、银行账号或完整含凭证 URL。

| 场景 | 应检查的连接 | 判定 |
|---|---|---|
| HSBC HK 页面/登录入口 | www.hsbc.com.hk、www.personal.hsbc.com.hk、hsbc.edge.sdk.awswaf.com | 均 direct；MITM 为关；不做转账验证 |
| ChatGPT 网页 | chatgpt.com 子域、auth.openai.com、oaistatic/oaiusercontent、Cloudflare/WorkOS | core 与共享依赖均命中 OpenAI；最终出口符合手选 |
| Codex | chatgpt.com / OpenAI 认证与 WebSocket | TCP/443 长连接稳定；不把节点测速通过当 API 可用 |
| 上传/下载 | 用户文件/CDN精确端点 | 与会话出口一致，不被 Microsoft/Global 偶然归类 |
| 企业内网 | 实际使用的内部域名 | 系统 split-DNS 和私网路由仍正常 |
| IPv6/UDP | 同业务 AAAA、QUIC 或语音 | 单独检查；没有日志不宣称全直连 |
| 通用服务 | Google、Microsoft、Apple、国内媒体、未知境外域名 | 分别进入指定组和 Final；无空策略组 |

大陆网络下 `direct` 无法保证 OpenAI/Claude 可用。若需要代理，优先选择有合法有效 TLS 配置的稳定节点。节点使用 `tls-verification=false` 时，QX 不验证代理服务器证书；应向提供方取得正确 SNI/证书或 pin。不要为修复这一项盲改连接参数，也不要复制此设置为新节点默认值。

验收只完成日常页面、认证和请求路由；银行交易成功、付费资格、平台地区支持不在规则静态测试的证明范围内。
