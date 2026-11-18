# 账号、安全认证与系统设置路线

NodeWall 的账号能力按阶段升级，先把入口、数据边界和恢复路径固定下来，再逐步启用高风险认证能力。每一阶段都可以单独回滚，不会因为配置 SMTP 或启用二次验证而替换现有登录链路。

## 第一阶段：账号中心与个人偏好

当前阶段已经提供独立的“账号”入口，包含当前账号、角色、会话状态、修改密码入口，以及个人主题和语言偏好。主题支持浅色、深色和跟随系统三种模式，主题属性写在页面根节点上，因此弹窗、表格、下拉框和后续页面使用同一组颜色变量。

主题偏好暂时保存在当前浏览器的 `localStorage`。这样不会把浏览器偏好误写入集群配置；账号级同步会在认证资料接口稳定后加入。

## 第二阶段：OTP/TOTP（已完成基础链路）

为用户生成一次性绑定密钥和 `otpauth://` URI，绑定过程要求当前密码或已有二次验证确认。密钥写入加密用户存储，验证码只在校验时短暂存在内存。登录、绑定、禁用和备用恢复码都需要限速并记录审计事件。

当前已经提供 OTP 密钥生成、验证码确认、恢复码一次性生成、登录校验、停用和状态查询。密钥和恢复码哈希写入加密用户存储，绑定密钥只在确认前保留在内存中。管理员强制策略会拒绝未完成绑定的配置，避免启用后把账号全部锁在登录页外。

登录时先完成账号、密码和安全验证码；验证码使用短期一次性挑战、来源绑定和失败限速，字符题使用更大的随机空间。验证码失败或过期后必须重新获取。如果账号需要 OTP，NodeWall 会跳转到独立的辅助验证页面输入 OTP 或恢复码，密码登录页不再嵌入 OTP 输入框。

接口：

```text
GET  /account/security
POST /account/otp/setup
POST /account/otp/verify
POST /account/otp/disable
POST /account/recovery-codes/regenerate
```

管理员策略会增加：是否强制二次验证、允许的验证方式、宽限期，以及是否对管理员强制启用。

## 第三阶段：Passkey/WebAuthn（已完成基础链路）

Passkey 使用成熟 WebAuthn 实现，不在 NodeWall 内保存私钥。服务端只保存凭证 ID、公钥、签名计数器、传输方式和最后使用时间。注册和删除要求当前密码或已验证的 OTP/Passkey，登录 challenge 设置短有效期并绑定当前会话和来源。

当前已经提供注册、凭证列表、删除和基于用户名的 Passkey 登录接口。凭证公钥及签名计数器由成熟 WebAuthn 库验证后写入加密用户存储，私钥永远不进入 NodeWall。Passkey 默认关闭，只有管理员在系统设置中完成条件检查并显式启用后，登录页才显示 Passkey 入口。生产使用必须配置 DNS RP ID 和 HTTPS；直接用 IP 地址时会明确拒绝注册。

例如管理端使用 `https://nodewall.example.com:8086` 访问时，可配置：

```text
NODEWALL_WEBAUTHN_RP_ID=nodewall.example.com
NODEWALL_WEBAUTHN_ORIGINS=https://nodewall.example.com:8086
```

浏览器访问 `https://192.168.x.x:8086` 时，WebAuthn 标准不允许把 IP 作为 RP ID；页面会直接提示切换到 DNS 主机名。一个账号可以连续登记多个设备或安全密钥，服务端按凭证 ID 独立保存并在账号页显示列表。

管理端的 Passkey 设置支持两种 TLS 模式：NodeWall 本机终止 TLS 时可以导入包含 DNS 名称的证书和私钥；Kubernetes Ingress 或其他反向代理终止 TLS 时选择代理模式，不需要在 NodeWall 导入证书。代理模式必须显式设置 `NODEWALL_TRUST_PROXY=true`，并由可信 Ingress 转发 `X-Forwarded-Proto: https`；直接暴露 NodeWall 时保持默认值 `false`，这样客户端伪造该请求头不会被当成 HTTPS。两种模式都不会关闭 IP 入口，IP 仍用于普通管理访问，Passkey 只在配置的 DNS HTTPS Origin 上工作。

接口：

```text
GET  /account/passkeys
POST /account/passkeys/register/options
POST /account/passkeys/register/verify
POST /account/passkeys/{id}/delete
POST /auth/passkey/login/options
POST /auth/passkey/login/verify
```

## 第四阶段：SMTP 与密码找回（已完成基础链路）

管理员可以配置 SMTP 主机、端口、STARTTLS/SMTPS、账号、发件人、邮件标题和模板。SMTP 密码使用现有安全存储加密，前端永远不回显密码。找回密码流程只对已验证邮箱生效，验证码保存哈希、十分钟内有效、一次性使用，并限制发送和尝试次数，响应不泄露账号是否存在。

当前已经提供管理员 SMTP 配置、测试发送、邮箱验证码绑定和找回密码。SMTP 密码使用现有安全存储加密，验证码只保存哈希、十分钟有效、一次性使用并限速；找回成功后会使该账号所有旧会话失效。

接口：

```text
GET  /settings/smtp
PUT  /settings/smtp
POST /settings/smtp/test
POST /auth/forgot-password/request
POST /auth/forgot-password/verify
POST /auth/forgot-password/reset
```

## 第五阶段：SMTP 临时出方向租约（已接入）

发送邮件时不关闭整个出方向防火墙，也不永久打开 SMTP 端口。NodeWall 解析 SMTP 主机名；当出方向策略正在强制执行时，先临时允许 `/etc/resolv.conf` 中 DNS 服务器的 UDP/TCP 53，再临时允许解析出的 SMTP IPv4 和端口，邮件发送成功或失败后都撤销租约，到期任务再次清理。出方向已经设置为永久开放（包括 `default_action=pass` 且没有显式拒绝）或处于观察模式时保持原状态，不新增临时规则。显式拒绝的 DNS 53、目标地址或 SMTP 端口不会被临时租约绕过；如果 DNS 本身被拒绝，发送会返回明确错误并保留原策略。

管理员设置页最终拆为：

- **系统设置**：认证策略、强制 MFA、SMTP、邮件模板、默认主题。
- **用户管理**：管理员单独管理多账号、角色、启停、密码重置和删除。
- **账号**：个人资料、密码、邮箱绑定、OTP 列表、Passkey 列表、恢复码。
- **个人偏好**：主题、语言、通知偏好。

邮箱绑定仅在 SMTP 已启用且配置有效时允许发送验证邮件；管理员账号可以在“账号”页面完成邮箱绑定，SMTP 未启用时会直接返回本地化提示。

在第二阶段以前，账号页上的 OTP/Passkey 项显示为规划状态，不提供没有后端校验的假按钮。

## 登录安全边界

当前登录链路的安全边界包括：Argon2id 密码哈希（旧 SHA-256 记录成功登录后自动迁移）、不存在账号时的 dummy 哈希校验、来源绑定的一次性验证码、按来源和动作限速、OTP/恢复码尝试上限、短期一次性 Passkey challenge、`HttpOnly`/`SameSite=Strict` 会话 Cookie，以及所有认证写请求的 CSRF Header 校验。修改密码、管理员重置密码、角色或启停状态变更、找回密码成功都会撤销受影响账号的旧会话。

这些措施不能替代网络边界：管理端应使用 HTTPS，限制 8086 等管理端口的来源，并把 SMTP、DNS 的临时放行交给现有防火墙策略。已经取得主机 root 权限的攻击者可以替换程序、读取配置或篡改本地存储，这属于主机失陷后的系统边界，不应把 NodeWall 当成 root 权限隔离方案。
