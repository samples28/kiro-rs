# kiro-rs 安全审计记录

审计日期：2026-09-05。基线：提交 `ee942df17ba3e3819f1232b249f29f5acf749bcc` 加当前工作区内容。审计前已有 `admin-ui/src/components/model-prices-dialog.tsx`、`src/admin/billing.rs`、`src/model/config.rs` 三处修改，均保留。本文只报告问题，没有修改业务代码或锁文件。

结论：存在需要修复的鉴权配置缺陷、请求资源消耗问题、敏感信息暴露及有条件的网络信任边界问题。没有确认非空独立密钥正常配置下的匿名后台接管、远程代码执行或任意本地文件读取。默认监听 `127.0.0.1`；是否可从公网访问取决于实际部署。

**范围与验证方式**

- 检查 Rust 请求入口、认证与管理路由、协议转换、事件流解析、凭据池、HTTP 客户端、文件持久化、日志、计费统计，以及 React 管理页面和构建配置。
- 通过 OSV 在线查询 Cargo 锁文件中 243 个注册包、npm 锁文件中 244 个包、pnpm 锁文件中 230 个包，并复核重要公告的触发条件和修复版本。锁文件命中不等于对应功能已编译启用或实际可利用。
- 使用本地 Node 做 UTF-8 边界、请求体尺寸及 URL 解析验证；没有向真实服务发送压力请求、窃取凭据或进行 SMB/NTLM 测试。
- 当前环境没有可用的 Cargo/Rust 工具链，未编译、运行 Rust 单元测试或进行服务端到端复现。`npm audit` 因代理 CONNECT 失败，依赖结果来自成功的 OSV 查询。以下区分源码确认、构造验证与仍需运行验证的影响。
- 严重性为结合本项目权限和默认配置的定性评估，不替代部署环境中的风险评级。

**主要问题一览**

| 编号 | 问题 | 严重性/前提 | 建议顺序 |
| --- | --- | --- | --- |
| A1 | 空字符串 API 密钥使 `/v1` 鉴权失效 | 中；配置明确为 `apiKey: ""`，后果可包括额度被匿名消耗 | 优先 |
| A2 | 历史工具名去重存在平方级 CPU 消耗 | 中；普通 API 密钥，默认转换路径可达 | 优先 |
| A3 | 标准模式前缀缓存无容量上限 | 中；普通 API 密钥、`cacheMode=standard` | 优先 |
| A4 | 日志输出完整上游凭据及部分其他密钥 | 中；调试日志开启及日志可被读取 | 优先 |
| A5 | 用户提供的 session 字符串触发 panic | 低；普通 API 密钥，默认影响连接任务 | 随输入校验修复 |
| A6 | 导入的区域字段可改变上游主机 | 条件性中危；导入不可信凭据配置/具有管理权限 | 随网络边界修复 |
| A7 | 远程 token 计数重定向携带自定义密钥头 | 条件性中危；启用该功能且跳转目标可被影响 | 随网络边界修复 |
| A8 | 浏览器长期保存敏感信息，退出后代理密码残留 | 低；共享浏览器配置或同源脚本读取能力 | 后续加固 |

**A1：空 API 密钥没有被拒绝**

证据：[main.rs:88](src/main.rs#L88) 只拒绝 `None`，允许 `Some("")`；[common/auth.rs:16](src/common/auth.rs#L16) 返回空 `x-api-key`；[anthropic/middleware.rs:54](src/anthropic/middleware.rs#L54) 比较空请求密钥和空配置密钥后放行。

在已设置 `"apiKey":""` 的本地测试实例上，可用以下请求验证。curl 的分号语法表示发送值为空的 header：

```powershell
curl.exe -H "x-api-key;" http://127.0.0.1:8990/v1/models
```

缺少 `apiKey` 会使程序退出；配置正常非空密钥不受此路径影响。管理密钥另有非空校验，不会因此直接开放 Admin API。

修复：在启动和状态构造时拒绝空白密钥，提取 header 时拒绝空值；推荐配置独立的高熵随机 API/Admin 密钥，并拒绝继续使用示例占位密钥。对校验失败返回明确错误，不要静默启动。

**A2：历史工具去重可造成 CPU 拒绝服务**

[converter.rs:193](src/anthropic/converter.rs#L193) 的 `collect_history_tool_names` 将工具名放入 `Vec`；每次加入前在 [第 200 行](src/anthropic/converter.rs#L200) 调用线性 `contains`。N 个不同工具名需要 `N(N-1)/2` 次比较。

攻击者可提交一条包含 N 个不同 `tool_use` 的 assistant 历史和一条包含对应 `tool_result` 的 user 消息。配对合法，避免被前面的孤立工具清理逻辑删除。每个名字短于 63 字节，避免名称缩短改变构造。请求在 [handlers.rs:224](src/anthropic/handlers.rs#L224) 同步执行转换，尚未调用上游或检查凭据冷却。

本地只生成 JSON、计算大小和比较次数，未运行压力测试：

| 不同工具数 | JSON 字节数 | 线性查重比较次数 |
| --- | ---: | ---: |
| 1,000 | 140,118 | 499,500 |
| 10,000 | 1,400,118 | 49,995,000 |
| 50,000 | 7,000,118（约 6.68 MiB） | 1,249,975,000 |

这些请求均小于 [router.rs:18](src/anthropic/router.rs#L18) 的 50 MiB 上限。大量同步比较占用 Tokio 工作线程；并发提交会影响其他请求。没有声称实测了具体耗时或服务宕机。

修复：用 `HashSet` 做去重并保留有序结果；在转换前限制消息、内容块、工具调用数量和字符串长度；在解析/转换前施加全局及调用方并发限制。仅限制请求字节数或开启上游凭据冷却不足以覆盖此路径。

**A3：标准模式缓存可被持续撑大**

[token_manager.rs:2983](src/kiro/token_manager.rs#L2983) 在标准模式使用全局 `HashMap<u64, Instant>`，在 [第 3023 行](src/kiro/token_manager.rs#L3023) 插入所有前缀，没有硬容量上限。更新由 [handlers.rs:273](src/anthropic/handlers.rs#L273) 在上游请求之前执行，上游失败也不撤回。

可构造 N 条 `{"role":"x","content":null}` 历史，首条内容设为变化的 nonce，最后追加正常 user 消息。[types.rs:207](src/anthropic/types.rs#L207) 接受任意字符串角色；[converter.rs:825](src/anthropic/converter.rs#L825) 忽略这些非法角色，发往上游的历史很小；但 [cache_usage.rs:58](src/anthropic/cache_usage.rs#L58) 仍对全部原始历史计算前缀并写缓存。改变首条 nonce 就会产生新的一批前缀。

本地尺寸验证：10 万条约 2.67 MiB，100 万条约 26.70 MiB，均在请求上限之内。大量条目在全局同步锁下插入，会增加内存和锁竞争。[第 3003 行](src/kiro/token_manager.rs#L3003) 的 TTL 清理使用 `retain`，不会自动收缩 HashMap 容量，所以过期后内存容量也可能保留。

这是非默认 `cacheMode=standard` 下的风险；默认 `fixed` 提前返回，不走此缓存写入。未进行真实 OOM 测试。

修复：拒绝非法 role，限制消息数；为缓存设置明确条目/内存上限和淘汰策略；仅基于验证后的请求建立缓存，并考虑上游成功后更新。入口限流与并发限制应覆盖转换和缓存阶段。

**A4：认证材料进入日志**

[main.rs:85](src/main.rs#L85) 用 `{:?}` 打印第一条完整凭据，[credentials.rs:14](src/kiro/model/credentials.rs#L14) 自动派生 `Debug`，字段包括 access token、refresh token、client secret、账号密码、代理密码和 Kiro API key。

只要设置 `RUST_LOG=debug` 就会记录这些值，**与 `debugLogEnabled=false` 无关**。通过 `KIRO_API_KEY` 环境变量注入的凭据会排在最前，因而也可能被输出。

此外，[main.rs:208](src/main.rs#L208) 默认 INFO 输出普通 API key 的前半部分；[main.rs:103](src/main.rs#L103) 和 [http_client.rs:79](src/http_client.rs#L79) 输出完整代理 URL，URL 内嵌的用户名密码会一起出现。前半个 key 不等同完整 key 泄露，但不应当记录。

攻击者需要读取日志平台、排障包或本地日志的能力。这些系统的权限往往比凭据文件更宽。

修复：删除凭据对象和密钥片段的日志，必要时只记录不可逆指纹；给凭据实现脱敏 `Debug`；代理 URL 仅记录 scheme/host/port。如果实际环境开过相关日志，应核查日志接触范围并轮换已暴露的认证材料。

**A5：UTF-8 字节截取导致 panic**

[converter.rs:178](src/anthropic/converter.rs#L178) 对 `metadata.user_id` 中 `session_` 后的内容直接取 `[..36]`。输入为 `session_` 加 35 个 ASCII `a` 再加汉字 `中` 时，后半段长 38 字节，第 36 字节落在汉字内部。

本地字节验证确认该位置不是 UTF-8 字符边界，Rust 对 `str` 执行这一切片会 panic。触发点在调用上游之前。默认 panic unwind/Tokio 任务隔离下，影响对应连接任务；没有证据表明单次请求会杀死整个进程或污染全局锁。

修复：用 `get(..36)` 安全截取，并用 `Uuid::parse_str` 严格校验；格式不合法时返回参数错误或按既定规则生成新会话 ID。当前仅统计长度与连字符数也不是完整 UUID 校验。

**A6：不可信凭据配置可改变上游目的地**

批量导入接受 `authRegion/apiRegion`，[admin/service.rs:289](src/admin/service.rs#L289) 原样复制；[credentials.rs:249](src/kiro/model/credentials.rs#L249) 返回未经校验的区域字符串；[endpoint/ide.rs:62](src/kiro/endpoint/ide.rs#L62) 将其拼进 URL，随后带 Bearer token 和对话内容发送。

本地 URL 解析例子（未发网络请求）：

```text
apiRegion = us-east-1@audit.invalid/x
拼接 URL = https://q.us-east-1@audit.invalid/x.amazonaws.com/generateAssistantResponse
实际 hostname = audit.invalid
```

[token_manager.rs:164](src/kiro/token_manager.rs#L164) 和 [第 255 行](src/kiro/token_manager.rs#L255) 的 OAuth 刷新 URL 有相同拼接方式，请求体携带 refresh token/client secret。

边界：普通 `/v1` 请求无法控制这些字段；需要管理员导入/添加凭据或修改配置。因此不能报告为匿名 SSRF。实际值得防范的场景是导入第三方凭据 JSON，随后其他使用者的对话被发给凭据供应方控制的主机。目标还需满足 TLS 校验及请求协议条件；程序自定义 Host，实际传输兼容性仍需隔离环境复测。

修复：服务端对白名单 AWS 区域进行严格校验；构造 URL 后校验 HTTPS、无 userinfo、主机属于确切的预期集合。不要只检查字符串是否包含 `amazonaws.com`。

**A7：远程计数 API 的重定向可能带走密钥和消息**

[token.rs:157](src/token.rs#L157) 向配置的计数 API 发送 `x-api-key` 和完整消息；[http_client.rs:52](src/http_client.rs#L52) 没有限制重定向策略。锁定的 reqwest 0.12.28 默认跟随跳转，其[跨主机敏感头清理代码](https://github.com/seanmonstar/reqwest/blob/v0.12.28/src/redirect.rs#L239) 不包含 `x-api-key`；307/308 还会保留 POST 请求体。

前提：启用可选的远程计数 API，且该端点的跳转可被攻击者影响或被误配置。默认未启用此功能，普通用户也不能直接指定计数地址。未进行带真实凭据的跳转测试。

修复：对携带认证材料的上游请求禁用重定向，或仅允许明确的同源 HTTPS 跳转；禁止 HTTPS 降级。自定义认证头不能依赖 HTTP 客户端的默认清理列表。

**A8：浏览器存储和退出清理不完整**

[storage.ts:11](admin-ui/src/lib/storage.ts#L11) 将管理员密钥长期保存到 localStorage；[第 21 行](admin-ui/src/lib/storage.ts#L21) 保存含代理密码的 `lastProxySettings`。[add-credential-dialog.tsx:101](admin-ui/src/components/add-credential-dialog.tsx#L101) 添加成功后自动记住代理设置，没有单独的记住密码选择。

[dashboard.tsx:185](admin-ui/src/components/dashboard.tsx#L185) 退出时删除管理员 key 和查询缓存，但不删代理设置；[proxy-page.tsx:155](admin-ui/src/components/proxy-page.tsx#L155) 的退出入口连查询缓存也未统一清除。共享同一浏览器配置的后来使用者可读取残留代理凭据；同源脚本也能读取 localStorage。余额缓存也会残留。

没有找到 XSS 路径，因此不能据此声称攻击者能直接远程盗取管理员 key。修复：默认不持久化代理密码；统一退出清理敏感存储；管理员使用短期会话，或至少改为页面生命周期内存存储。若改为 Cookie 会话，应同时设计 CSRF 防护。

**依赖公告与实际风险**

| 依赖/锁定版本 | 官方公告 | 修复下限 | 本项目中的条件和限制 |
| --- | --- | --- | --- |
| `bytes 1.11.0`，[Cargo.lock:171](Cargo.lock#L171) | [RUSTSEC-2026-0007](https://rustsec.org/advisories/RUSTSEC-2026-0007.html) | `1.11.1` | release 下 reserve 整数溢出可产生未定义行为；需接近 usize 上限的容量。本项目解码器先限制为 16 MiB，未发现可触发该容量的直接路径，不能称已确认 RCE。 |
| `h2 0.4.13`，[Cargo.lock:518](Cargo.lock#L518) | [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | `0.4.16` | 未消费的 HTTP/2 流可无限排队空 DATA 帧。运行时 reqwest 启用 http2；需要恶意对端和未消费流条件，未验证匿名入站可利用。官方评级 Low。 |
| `rustls-webpki 0.103.8`，[Cargo.lock:1322](Cargo.lock#L1322) | [0098](https://rustsec.org/advisories/RUSTSEC-2026-0098.html)、[0099](https://rustsec.org/advisories/RUSTSEC-2026-0099.html) | `0.103.12`；建议 `0.103.13+` | URI/DNS 名称约束验证缺陷，需受信 CA 误签并通过签名验证。不能用普通自签证书直接中间人攻击。另命中的 CRL 公告 0049/0104 在本项目未配置 CRL 的用法中未证实可达。 |
| `vite 5.4.21`，[npm lock:3826](admin-ui/package-lock.json#L3826)、[pnpm lock:1377](admin-ui/pnpm-lock.yaml#L1377) | [GHSA-v6wh-96g9-6wx3](https://github.com/advisories/GHSA-v6wh-96g9-6wx3) | `6.4.3` / `7.3.5` / `8.0.16` | Windows 开发机的 launch-editor 接受 UNC 路径，可能向攻击者 SMB 服务发送 NTLMv2 认证响应。需 dev server 运行、NTLM 可用且攻击网页可触发请求；不要求 dev server 对公网监听。生产 Rust 静态文件服务不包含该中间件。 |
| 同上 | [GHSA-4w7w-66w2-5vf9](https://github.com/advisories/GHSA-4w7w-66w2-5vf9)、[GHSA-fx2h-pf6j-xcff](https://github.com/advisories/GHSA-fx2h-pf6j-xcff) | 统一升级至上述 Vite 修复版本 | 开发服务器路径穿越、Windows NTFS ADS/8.3 名称绕过文件拒绝列表。公告要求相关开发服务对网络暴露；仓库没有配置 server.host。 |
| `axios`：npm `1.17.0`，pnpm `1.13.2` | [GHSA-mmx7-hfxf-jppx](https://github.com/advisories/GHSA-mmx7-hfxf-jppx)、[GHSA-42h9-826w-cgv3](https://github.com/advisories/GHSA-42h9-826w-cgv3) 等 | `1.18.0` | 前者需要预先存在原型污染，后者需要不可信 FormData 字段转换。本项目是固定同源 URL 和普通 JSON 请求，未发现对应可控入口；应更新，但不能称已发现 Axios SSRF。 |
| `rollup`：pnpm `4.54.0`，npm `4.61.1` | [GHSA-mw96-cpmx-2vgc](https://github.com/advisories/GHSA-mw96-cpmx-2vgc) | `4.59.0` | pnpm 版本命中构建输出路径穿越；需控制输入别名/chunk 名/插件，未发现普通请求可控制构建路径。 |

其他条件性命中：`anyhow 1.0.100` 的 [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190.html) 修于 1.0.103，本仓库未使用触发所需的 `downcast_mut`；`rand 0.9.2` 的 [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html) 修于 0.9.3，未发现所需的 logger/RNG 重入条件；`quinn-proto 0.11.13` 的 [0037](https://rustsec.org/advisories/RUSTSEC-2026-0037.html)/[0185](https://rustsec.org/advisories/RUSTSEC-2026-0185.html) 可升级至 0.11.15，但项目未开启 reqwest http3；`esbuild 0.21.5` 的 [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99) 修于 0.25.0，需启用 esbuild 自带 serve，仓库用法未发现该入口。

两套前端锁文件有明显漂移。只审计或更新 npm 锁不能保护实际用 pnpm 的构建；应选定包管理器并在 CI 强制锁定。Vite 修复涉及主版本升级，需要同步核对插件、Node 版本和构建兼容性。上述版本是本次公告的修复下限，不代表必须直接升级到最新主版本；未在本次修改锁文件。

**其他值得处理的事项**

- `direct` 语义： [credentials.rs:260](src/kiro/model/credentials.rs#L260) 将直连变为 `None`，HTTP builder 没有 `.no_proxy()`，仍可能采用环境/系统代理。这是配置语义缺陷；TLS 校验仍开启，不能推导为代理能自动读取所有明文。
- 文件权限： [token_manager.rs:1645](src/kiro/token_manager.rs#L1645)、[proxy_pool.rs:240](src/admin/proxy_pool.rs#L240) 直接写明文秘密。Unix 常见 umask 022 下新建文件可能为 0644，Windows 取决于目录 ACL；已有文件会保留原权限。建议只允许服务用户读写，并采用原子替换避免并发/中断导致文件损坏。
- 误提交风险：代理池会生成含密码的 `proxies.json`，但 `.gitignore` 没有排除该文件。当前 Git 跟踪文件里未发现它，不能声称已经泄露。应补充忽略规则和秘密扫描。
- 日志隐私和磁盘： [debug_log.rs:100](src/common/debug_log.rs#L100) 对完整请求/响应直接落盘，无脱敏、轮转和总大小限制。两个日志开关默认关闭；开启后应设置保留期、大小上限和权限。
- 管理页缺少 `CSP frame-ancestors`/`X-Frame-Options`： [admin_ui/router.rs:72](src/admin_ui/router.rs#L72)。建议拒绝被 iframe 嵌入；实际点击劫持是否能复用登录状态受浏览器存储分区及站点关系影响，不能当作无条件后台接管。
- 示例配置中的 API/Admin key 为固定值；直接复制后对外开放会使用公开密钥。部署应生成新密钥。本次没有读取到实际线上配置，不能认定线上正在使用示例值。
- 服务自身使用普通 HTTP。跨主机提供服务时需要在部署入口配置 HTTPS，否则请求头密钥及内容缺少传输保密；默认本机监听减小了暴露面。未检查外部网关实际 TLS 配置。
- `max_tokens` 目前主要被读取和记录，没有看到转换为上游生成限制或本地输出硬限制。不要把该字段当作可靠的费用/资源上限。
- 计费是估算统计：流式费用在 [stream.rs:1190](src/anthropic/stream.rs#L1190) 的最终事件阶段记录，客户端提前断开会使该回调可能不执行；[billing.rs:89](src/admin/billing.rs#L89) 对缺少价格的模型直接跳过。若要把此统计用于向客户结算，应另行补齐中断结算、价格完整性、持久化和可信 token 用量；这里没有余额扣减逻辑，不能表述为已确认绕过余额。

**已核实的防护与未确认项**

- Admin 路由整体使用独立的管理密钥中间件；正确配置不同的非空密钥时，未发现普通 API key 越权管理凭据的路径。
- 鉴权使用常量时间字节比较；`/v1` 开放 CORS 本身不会给外部网站管理员密钥，也不足以证明 CSRF。
- 没有发现应用源码中的 shell 命令执行、动态代码求值或直接 SQL 拼接入口。
- React 页面未发现 `dangerouslySetInnerHTML`、不可信动态脚本等直接 XSS sink。
- 生产静态文件来自 rust-embed，并检查路径中的 `..`，未发现读取任意操作系统文件的路径。
- HTTP 客户端没有显式关闭证书校验。事件帧有长度、边界和 CRC 校验，解码缓冲区有 16 MiB 上限；非流式路径在进入解码器前仍先完整读取响应，不应将解码上限等同完整 HTTP 响应上限。

**建议实施和复测顺序**

1. 先修输入边界：拒绝空密钥和非法 role，安全解析 UUID，限制消息/工具/内容块数量；将工具去重改为 HashSet，并给标准缓存设置硬容量上限。
2. 删除密钥日志，补齐敏感文件权限和浏览器退出清理；核查实际环境是否产生过含密钥的日志。
3. 更新 Cargo 运行时依赖及 Vite，统一前端锁文件；在可用构建环境运行 `cargo test`、前端构建和依赖审计。升级 Vite 时同时验证 Node/插件兼容性。
4. 校验区域和最终 URL，对携密钥请求限制重定向；复测第三方凭据导入和远程计数路径，使用假密钥、隔离 HTTPS 服务。
5. 用边界用例验收：空配置不得启动；异常 UTF-8/非法角色返回受控错误；超量内容块在转换前拒绝；缓存始终不超过设置上限；日志和退出后存储不含秘密。仅在隔离测试环境做受控并发/内存测试。

本报告是当前源码和锁文件的审计结果；部署端口、网关、系统 ACL、实际启用功能及真实账号状态仍需结合部署环境验证。
