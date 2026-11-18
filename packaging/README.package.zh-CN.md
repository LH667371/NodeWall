# NodeWall 打包产物使用说明

这个压缩包只用于部署，不包含源码开发说明。

发布新版本时只需修改仓库根目录的 `VERSION`。控制台、节点心跳和默认压缩包文件名
都从这里取版本号。发布流水线需要追踪构建或复现固定构建时，可通过
`NODEWALL_PACKAGE_REVISION` 和 `NODEWALL_PACKAGE_LABEL` 显式指定构建标识。

## 包内内容

- `bin/nodewall`：统一运行与运维二进制
- `README.md`、`README.zh-CN.md`：运维说明

文件名含 `_offline_` 的离线包还包含：

- `clamav/engines/`：适用于 `amd64` 和 `arm64` 的私有 ClamAV 运行时
- `clamav/database/`：打包时已校验签名的 `main`、`daily`、`bytecode` 完整数据库
- `clamav/NOTICE.md`：第三方组件和源码信息
- `clamav/source/`：ClamAV 对应源码及 Alpine 构建补丁

文件名含 `_update_` 的普通更新包不包含 `clamav/`。更新时会保留目标节点已有的引擎和数据库；
首次离线部署 ClamAV 时请使用离线包。任意已注册节点具备资源后，其他节点（包括原管理节点）
会在启动时及每 2 分钟自动同步缺失或较旧的引擎和病毒库，入群完成后无需手工复制。

Ubuntu 和 CentOS 可使用对应架构的离线包安装 ClamAV；无需另外安装系统 ClamAV，也不会替换
系统的 `glibc`。已在 CentOS 7 内核 3.10 上验证私有运行时及数据库识别。安装后由 NodeWall
Agent 启动私有 `clamd`，数据保存在 `/var/lib/nodewall/clamav`，不修改已有 ClamAV 配置。
FreshClam 默认使用包内的公共 CA 证书；如需使用企业代理的证书链，可在 NodeWall 环境中设置
`NODEWALL_CLAMAV_CA_FILE` 指向包含相应根证书的 PEM 文件。
首次加载完整数据库需要一定时间和内存；建议为宿主机预留约 3–4 GiB 可用内存和足够磁盘空间。
扫描结果中的引擎状态会显示加载或同步失败，不能把未运行的特征扫描当作安全结论。

管理节点使用 FreshClam 每小时检查官方更新；集群节点通过凭据及固定证书的 HTTPS 通道从
其他已注册 Agent 获取资源并校验摘要。离线包尚未在提供方加载也可以分发，接收方仍需完成校验。
更新会比较引擎发行版本及每份数据库版本，验证原始 CVD 签名并测试整套数据库加载后再切换，
保留上一套作为回退。网络断开时继续使用上次可用的数据库，恢复连接后自动重试。只分发
`bin/nodewall` 的单文件模式和普通更新包不包含离线引擎和数据库；缺少这些资源的节点需由
其他已注册节点提供，或使用离线包部署。引擎升级后会自动重启私有 `clamd`；可通过
`journalctl -u nodewall-agent -f` 查看同步日志。
ClamAV 特征库不能保证识别未知病毒，扫描仍会结合行为和持久化检查。

## 安装

建议先执行预检：

```sh
sudo ./bin/nodewall preflight
```

预检失败时，安装器也会拒绝继续安装；修复失败项后再执行：

```sh
sudo ./bin/nodewall install --password 'change-me'
```

默认会安装到：

- 二进制目录：`/opt/nodewall/bin`
- 配置目录：`/etc/nodewall`
- systemd 服务：`nodewall-agent.service`、`nodewall-server.service`

默认使用 systemd 管理服务。需要避开 systemd 时，可以在安装参数中显式选择 SysV：

```sh
sudo ./bin/nodewall install --service-manager=sysv --password 'change-me'
```

该模式写入 `/etc/init.d/nodewall-agent` 和 `/etc/init.d/nodewall-server`，使用
`chkconfig` 或 `update-rc.d` 注册开机启动，并写入 `/etc/cron.d/nodewall` 作为
`@reboot` 兜底。两个进程异常退出时会自动重启，日志分别写入
`/var/log/nodewall/agent.log` 和 `/var/log/nodewall/server.log`。如果传入
`--enable-services=false`，安装器不会注册任何开机启动入口。

默认情况下：

- Web 服务监听 `0.0.0.0:8086`，局域网其他设备可以访问
- 新安装的安全 all-in-one 节点在识别到可用 IPv4 地址时，agent 监听 `0.0.0.0:9080` 并向集群通告该地址；显式指定监听地址、关闭 TLS 或无法识别地址时保留相应的原有设置。显式监听 `127.0.0.1` 时其他管理节点无法直接访问该 agent。
- 拦截日志写入 `/var/lib/nodewall/logs`
- 日志状态保存到 `/etc/nodewall/drop-log-state.json`
- 默认保留 `7` 天，每 `30` 秒刷盘一次

## ZStack 旧内核兼容模式

安装默认使用 XDP + TC eBPF，不会根据内核自动切换到 iptables。低于 `4.18` 的内核会在
预检阶段失败；只有明确指定 `--dataplane iptables` 才会启用兼容模式：

```sh
sudo ./bin/nodewall install \
  --dataplane iptables \
  --default-interface em1 \
  --password 'change-me'
```

该模式仅面向非 Kubernetes 的 ZStack/CentOS 主机。它在 `filter/INPUT`、`filter/OUTPUT`
维护独立的 `NWRAW_*`、`NWRAW_OUT_*` 链，利用连接跟踪保留 DNS、HTTPS 和 SSH 回包，
显式封禁及端口拒绝仍优先。虚拟机转发和 ZStack 协议 `253` 的网络日志路径保持原有处理。
升级会删除旧版 NodeWall 的 `raw/mangle` 私有链及跳转，不删除 ZStack 规则，也不写入
`/etc/iptables`。观察模式不会安装 `DROP` 规则。不要将 bridge、`vnic*`、`outer*` 等虚拟接口作为 `--default-interface`
参数。Kubernetes 节点不要使用该模式，以免与 CNI 和 kube-proxy 的规则边界冲突。

远程加入时，脚本会把 ZStack bridge（例如 `br_eno1`）解析为物理端口（例如 `eno1`），
并保留 bridge 上的管理地址。其他物理网卡可在链路恢复后从节点管理页面逐个挂载。
如果当前 systemd 总线暂时不可用，脚本仍会直接启动 Agent 和管理 Web 服务，并将日志写入
`/var/log/nodewall/agent.log`、`/var/log/nodewall/server.log`；同时只要主机提供
`systemctl`，仍会写入并启用两个 unit，避免 CentOS 重启后服务保持 disabled。

主节点和加入集群的备用管理节点统一从 `8086` 开始选择 Web 端口；升级或重新注册时，旧的 `8080` 至 `8085` 配置也会迁移到 `8086` 之后。
选中的管理 Web 地址会随 Agent 心跳上报，并显示在集群节点列表中。节点也会持续同步管理节点快照；主节点离线时，可以从其他节点继续打开控制台。

集群基线默认保留管理端 TCP `8082`，新节点加入和管理端重启时会自动补齐已有节点的互联规则。
新节点不会因为加入就立即开启拦截；可在页面永久启用，或先选择 `1` 至 `120` 秒试运行。
试运行未确认时会自动恢复到试运行前状态，避免 ZStack 管理链路被误断。

## 修改密码

```sh
sudo /opt/nodewall/bin/nodewall set-password --file /etc/nodewall/auth.json --password 'new-password'
```

## 状态与凭证保护

生产安装会在 `/etc/nodewall/cluster.key` 生成集群密钥，并使用 AES-GCM 加密管理状态、节点登记凭证、登录账号和认证设置。每个文件保留 `.bak.1` 至 `.bak.3` 三代轮换副本；启动时会校验认证标签，主文件损坏时自动尝试恢复副本。

请把 `cluster.key` 与配置目录纳入受控备份。已经取得主机 root 权限的攻击者仍能读取或删除本机密钥，因此高安全场景应把密钥和快照复制到独立的备用管理节点或外部密钥系统。

## 更新

把新的压缩包解压后，直接在新目录里执行：

```sh
sudo ./bin/nodewall update
```

如果主管理节点已经从旧的 `8080` 迁移到 `8086+`，而节点仍保存旧地址，
首次更新旧节点时请显式指定当前管理地址：

```sh
sudo ./bin/nodewall update --manager-url https://MANAGER_HOST:8086
```

该地址会写入节点配置，之后心跳和更新请求都会使用当前管理端口。

更新会保留现有配置、密码和端口，只覆盖：

- `/opt/nodewall/bin/nodewall`
- `/opt/nodewall/web`
- `/opt/nodewall/bpf/gen/xdpacl_bpfel.o`
- systemd unit 文件

前端资源会写入当前 `NODEWALL_WEB_DIR` 配置的目录；旧安装如果仍指向历史 Web 目录也会原地刷新，服务重启后会直接加载新版页面。

主管理节点执行更新后，已加入节点会通过心跳比较版本并自动滚动升级；集群页面会显示管理端版本和每个节点上报的版本。更新会同时校验安装包标记和当前进程编译版本，避免 CentOS 上 systemd 总线不可用或 unit 处于 inactive 时只替换文件而留下旧 Agent/Web 进程；直接启动的进程和旧版 `nodewall.tmp.*` 执行文件会在新服务启动前被回收。

默认会对正在运行的服务执行就地重启。如果你只想先替换文件，不立刻重启：

```sh
sudo ./bin/nodewall update --restart-services=false
```

## 端口冲突处理

所有 NodeWall 管理服务从 `8086` 开始选择端口；如果端口被占用，会继续顺延到下一个空闲端口。升级时会自动迁移旧的 `8080` 至 `8085` 配置。

如果你想明确指定端口，也可以这样安装：

```sh
sudo ./bin/nodewall install \
  --server-addr 0.0.0.0:18080 \
  --agent-addr 127.0.0.1:19080 \
  --agent-url http://127.0.0.1:19080 \
  --password 'change-me'
```

安装器会在写入 `/etc/nodewall/nodewall.env` 之前先检查端口是否可用。

如果安装后还要改端口，修改 `/etc/nodewall/nodewall.env` 后重启服务：

```sh
sudo systemctl restart nodewall-agent.service
sudo systemctl restart nodewall-server.service
```

## 查看服务

```sh
systemctl status nodewall-agent.service
systemctl status nodewall-server.service
```

## 管理页面

安装完成后，在浏览器进入 NodeWall Web 页面，使用左侧的 `管理` 页面可以：

- 修改登录密码
- 开关持久化拦截日志
- 修改日志保留天数
- 修改刷盘间隔
- 查看当前日志目录
- 清空已经落盘的历史拦截日志

如果你更喜欢手动改环境文件，也可以编辑：

```sh
sudo vi /etc/nodewall/nodewall.env
```

常用日志配置：

- `NODEWALL_LOG_DIR`
- `NODEWALL_DROP_LOG_ENABLED`
- `NODEWALL_DROP_LOG_RETENTION_DAYS`
- `NODEWALL_DROP_LOG_FLUSH_INTERVAL`
- `NODEWALL_DROP_LOG_STATE`

常用登录防护配置：

- `NODEWALL_AUTH_SETTINGS_FILE`
- `NODEWALL_SSH_AUTH_LOG`（留空时自动选择 `auth.log`、`secure` 或 `journalctl`）

管理页里的“登录防护”面板可以直接调整：

- 锁定前最大失败次数
- 失败统计窗口
- 锁定时长
- 当前活跃锁定数量

修改后重启服务：

```sh
sudo systemctl restart nodewall-agent.service
sudo systemctl restart nodewall-server.service
```

如果需要直接查看日志文件：

```sh
ls -lah /var/lib/nodewall/logs
tail -f /var/lib/nodewall/logs/drop-$(date +%F).jsonl
```

## 卸载清理

```sh
sudo ./bin/nodewall cleanup
```

卸载会先停止服务和直启进程，恢复 NodeWall 管理的 `sshd`、SFTP 和 root 控制台密钥，再删除运行文件。恢复校验或 `sshd` reload 失败时命令会保留文件并返回错误，避免留下引用不存在 `/opt/nodewall/bin/nodewall` 的 SSH `ForceCommand`。

若旧版本已经删除二进制而 SSH 仍引用旧包装器，请从本地控制台备份并删除 `sshd_config` 中 `# BEGIN NODEWALL SSH POLICY` 到 `# END NODEWALL SSH POLICY` 的块，执行 `sshd -t` 后 reload SSH；不要先删除 `/etc/nodewall`，SFTP 原始配置可能仍保存在其中。
