# 原配置重写与脚本审查

审查时间：2026-10-14。全部原始远程条目（启用与禁用）均尝试下载；静态读取内容与嵌套脚本，不执行第三方代码。新路由基线移除所有重写/任务依赖。可达不证明功能正确或无恶意；压缩/生成脚本未做形式安全证明。

| 原配置行 | 资源 | 原状态 | HTTP | 静态行为与结论 |
|---:|---|---|---:|---|
| 77 | [YoutubeAds.conf](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/YoutubeAds.conf) | 启用 | 200 | YouTube protobuf 响应修改、广告统计拒绝、video URL 302；依赖 Maasea 的可变 master 脚本。 |
| 80 | [Weibo.adblock](https://cdn.jsdelivr.net/gh/sve1r/Rules-For-Quantumult-X@develop/Rewrite/AdBlock/Weibo.adblock) | 关闭 | 200 | 旧微博集合；含脚本与JSON替换，可达但关闭。 |
| 83 | [Youtube.adblock](https://cdn.jsdelivr.net/gh/sve1r/Rules-For-Quantumult-X@develop/Rewrite/AdBlock/Youtube.adblock) | 关闭 | 200 | 旧 YouTube 脚本，与启用版本功能重叠；保持关闭。 |
| 87 | [BilibiliAdsLite.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/BilibiliAdsLite.conf) | 关闭 | 404 | 404；禁用条目，不是当前请求失败的直接原因。 |
| 88 | [spotify.conf](https://raw.githubusercontent.com/app2smile/rules/master/module/spotify.conf) | 启用 | 200 | 修改 Spotify 请求头、bootstrap/protobuf 响应及JSON字段；不是普通分流；脚本内有 eval 机制，未执行。 |
| 89 | [ForOwnUse.conf](https://github.com/ddgksf2013/dev/raw/master/ForOwnUse.conf) | 关闭 | 200 | 可达，订阅/VIP响应修改集合；关闭，不纳入稳定路由。 |
| 93 | [StartUpAds.conf](https://gist.githubusercontent.com/ddgksf2013/12ef6aad209155e7eb62c5b00c11b9dd/raw/StartUpAds.conf) | 关闭 | 404 | 404；不再保留失效条目。 |
| 94 | [CaiYunAds.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/CaiYunAds.conf) | 关闭 | 200 | 彩云广告/响应修改；关闭。 |
| 95 | [Zhihu.Adblock.js](https://gist.githubusercontent.com/ddgksf2013/d43179d848586d561dbb968dee93bae8/raw/Zhihu.Adblock.js) | 关闭 | 404 | 404；不再保留失效条目。 |
| 96 | [YoutubeAds.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/YoutubeAds.conf) | 关闭 | 200 | 与已启用 YoutubeAds 完全同 SHA256，只是URL别名重复；关闭。 |
| 97 | [WeiboAds.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/WeiboAds.conf) | 关闭 | 200 | 微博 URL 拒绝+JS/JSON响应修改；关闭。 |
| 98 | [Ximalaya.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/Ximalaya.conf) | 关闭 | 200 | 喜马拉雅广告响应修改；关闭。 |
| 99 | [AmapAds.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/AmapAds.conf) | 启用 | 200 | 高德导航/推荐/天气接口修改或拒绝，并有 HTTP amdc 响应脚本；混入 host-suffix direct 行需独立治理。 |
| 100 | [NeteaseAds.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/NeteaseAds.conf) | 关闭 | 200 | 网易云响应脚本；关闭。 |
| 101 | [GoofishAds.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/GoofishAds.conf) | 启用 | 200 | 闲鱼 jsonjq 改写与 HTTP amdc 脚本；后者匹配多个域的 /amdc/mobileDispatch，不限闲鱼。混入 iyes.youku.com reject 行需独立filter资源治理。 |
| 105 | [Q-Search.conf](https://github.com/ddgksf2013/Rewrite/raw/master/Html/Q-Search.conf) | 启用 | 200 | DuckDuckGo 查询跳转；最后把普通查询重定向 Google；部分目标使用HTTP，会改变实际访问站点。 |
| 106 | [Douban.conf](https://github.com/ddgksf2013/Rewrite/raw/master/Html/Douban.conf) | 启用 | 200 | 豆瓣网页 HTML 响应注入/修改；共享远程JS。 |
| 107 | [General.conf](https://github.com/ddgksf2013/Rewrite/raw/master/Html/General.conf) | 启用 | 200 | google.cn/g.cn 302到google.com；hostname只列www.google.cn，其他HTTPS主机未必触发。 |
| 111 | [XiaoHongShuAds.conf](https://github.com/ddgksf2013/Rewrite/raw/master/AdBlock/XiaoHongShuAds.conf) | 关闭 | 404 | 404；不再保留失效条目。 |
| 112 | [baiduCloud.adblock.js](https://gist.githubusercontent.com/ddgksf2013/f43026707830c7818ee3ba624e383c8d/raw/baiduCloud.adblock.js) | 关闭 | 404 | 404；不再保留失效条目。 |
| 113 | [UnblockURLinWeChat.conf](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/Function/UnblockURLinWeChat.conf) | 关闭 | 200 | 微信URL处理脚本；关闭。 |

## 间接依赖

可获取重写文件中识别并检查了 19 个唯一实际脚本/JSON依赖；相同脚本复用仅下载一次。启用部分涉及 YouTube、Spotify、amdc、amap、douban。脚本 URL 仍指向可变分支，即便外层配置固定也不能冻结其内部依赖。

启用 YouTube 的主机范围为 googlevideo/youtube/youtubei.googleapis.com；Spotify、高德、闲鱼、DuckDuckGo、豆瓣、Google 各自有范围。当前取证未发现 HSBC/OpenAI 直接落入这些启用的主机集合，最近相关连接 mitm_is_on=0，所以不把它们认定为 HSBC 漏分流根因。QX 全局 HTTP 抓取的额外 * 是另一个独立开关，应在设备验收时关闭。

Goofish 的 HTTP /amdc/mobileDispatch 通配规则范围较大，amdc.js 会返回空响应来改变 HTTP DNS 行为，可能影响同接口约定的其他应用。AmapAds 和 GoofishAds 还混入分流行；不要假设这些行作为 rewrite 资源一定进入 filter 链。

KOP-XIAO resource-parser 固定在 29ef7480402d145396c84082a6f9316fe12931d4：用于节点格式转换，约270KB；静态阅读了过滤/重命名等入口，未执行。保留为可选节点解析功能。IP_API 同版本通过明文 ip-api 查询出口归属；纯路由基线删除。streaming-ui-check 原来引用 master，并会向 Netflix/YouTube/Disney/ChatGPT 等发请求，ChatGPT 检查仍使用旧 chat.openai.com 入口；不是业务登录可用性的证明，基线删除。

初次审计时 34 个图标地址均可达。策略模板现已恢复原配置的 Koolson/Qure 彩色图标源，覆盖现有 15 个策略组；图标只影响显示，不改变分流或策略选择。未恢复已删除的策略组或重写项。

MITM 的 p12 和 passphrase 是 CA 私钥相关材料，只存在原私有配置，本仓库和报告不收录。
