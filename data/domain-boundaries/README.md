# 离线域名边界快照

`audit_semantics.py` 使用这些固定数据验证公开域名的 TLD 和注册边界，校验不访问 DNS 或网络。`snapshot.json` 记录抓取日期、不可变 PSL 提交和文件 SHA-256。IANA 原始文件头包含其版本；没有可用 TLD 不能被解释为已注册公开域名。

- `tlds-alpha-by-domain.txt`：IANA Root Zone 已委派 TLD 的事实清单。
- `public_suffix_list.dat`：Public Suffix List 的 ICANN 和 PRIVATE 部分；保留原始文件与 MPL-2.0 许可。完整许可证见 `../../LICENSES/publicsuffix-MPL-2.0.txt`。
- `brand-tlds.json`：仅对逐个核验过 IANA 注册局的 `.apple`、`.google`、`.microsoft`，允许将企业顶级域作为明确的服务边界。没有根据名字推断其他品牌域归属。当前规则未要求使用这些顶级域。

PSL 的 `*.ck` 和 `!www.ck` 等通配／例外语义由审查器解析。PRIVATE 后缀代表租户共享服务边界，不代表其中所有租户属于该供应商应用。普通注册域是否属于目标服务仍需官方资料和人工评审；本检查不证明域名仍提供服务。

更新时同时抓取 IANA 和固定提交版本 PSL，核对差异、许可证与品牌注册局证据，再更新哈希及日期并运行全部测试。不要只更新哈希来消除失败，也不要自动把所有顶级域当成可以整域分流的服务。
