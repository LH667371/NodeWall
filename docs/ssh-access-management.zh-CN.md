# SSH 登录方式与公钥管理

SSH 防护页面现在提供两项按节点管理的 SSH 访问控制：

- **密码登录**：显式选择允许密码认证或仅允许公钥认证。选择公钥模式时会同时关闭 `PasswordAuthentication`、`KbdInteractiveAuthentication` 和 `ChallengeResponseAuthentication`，避免 PAM 键盘交互继续接受密码。修改前必须输入当前管理端密码；节点会先执行 `sshd -t` 和 `sshd -T`，校验失败或 reload 失败会恢复原配置。
- **服务器公钥**：查看、添加和删除当前节点 root 的 `/root/.ssh/authorized_keys`。接口只接受纯公钥，不接收私钥或带授权选项的新密钥；文件使用原子替换。列表会按指纹标出“当前控制台密钥”和“历史 NodeWall 密钥”，当前密钥或密码登录已关闭时的最后一把公钥需要当前管理密码确认；历史 NodeWall 密钥可以直接清理，不会因为 `nodewall-console` 备注被错误拦截。

公钥列表以节点本地 `authorized_keys` 为准，管理端不保存私钥。当前密钥状态由节点读取配置中的私钥并计算 SHA-256 指纹得出，读取列表不会生成新密钥；无法读取当前私钥的 agent-only 节点会把 NodeWall 公钥标为“需确认”，不会默认放行删除。已有带 `from=`、`restrict` 等选项的公钥会保留原始选项并在列表中展示，删除时按 SHA-256 指纹定位。

卸载时会清理所有使用保留备注 `nodewall-console` 的历史和重复条目；管理员使用其他备注的公钥会保留。新增配置文件必须同步加入安装清单和卸载清理清单，避免升级后留下 NodeWall 残留状态。

启用 SSH 命令审计后，NodeWall 会保留 sshd 分配的 PTY。旧版本的审计包装器把交互 shell 输出接成 pipe，执行 `vi` 时会出现 `Vim: Warning: Output is not to a terminal`；升级后重新建立 SSH 连接即可使用正常的终端编辑器。
