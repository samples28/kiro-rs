# kiro-rs

一个用 Rust 编写的 Anthropic Claude API 兼容代理服务，将 Anthropic API 请求转换为 Kiro API 请求。

管理后台的“添加凭据”右侧提供“登录”菜单，支持 Kiro 账号（Google / GitHub）、AWS Builder ID 和企业 IAM Identity Center SSO。授权完成后自动验证、保存并启用凭据，按现有设置分配代理并刷新余额。

使用旧版单对象凭据配置时，新增凭据会自动将配置转换为数组，并保留原有凭据。

- Kiro 账号：打开登录页完成授权；本机可自动接收回调。远程访问、Docker 或端口转发时，如果跳转到无法访问的 localhost / 127.0.0.1 地址，复制该页面地址栏中的完整 URL，粘贴到后台“回调地址”后点击“完成登录”。
- AWS Builder ID：SSO Start URL 留空，在授权页确认设备验证码。
- 企业 SSO：填写组织的 HTTPS SSO Start URL 和对应 AWS Region，再完成设备授权。
- 需要切换账号时可勾选“使用无痕窗口登录”，复制链接到浏览器的无痕 / 隐私窗口打开。

前端资源随 Rust 程序嵌入，更新后需先在 `admin-ui` 执行 `npm ci`、`npm run build`，再在项目根目录执行 `cargo build --release` 并重启服务。

模型映射中，Free 与付费账号平级参与调度，按配置的优先级或均衡规则选择账号。选中 Free 账号后，使用 Free 映射右侧的模型；其他账号使用通用映射。Free 规则匹配客户端原始模型名，忽略大小写并采用包含匹配，多条命中时使用第一条，没有匹配规则则跳过 Free 账号。

例如，通用映射配置 `claude-opus-4-6 → claude-opus-4.6`，Free 映射配置 `claude-opus-4-6 → claude-sonnet-4.5`：同一个 Opus 4.6 请求分配给 Free 时实际调用 Sonnet 4.5，分配给付费账号时实际调用 Opus 4.6。仅有 Free 账号也适用；切换账号重试时会重新应用对应映射。保存映射后，后续请求即可使用新规则。

---
