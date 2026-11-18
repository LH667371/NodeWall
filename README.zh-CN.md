# NodeWall

NodeWall 是一个面向 Kubernetes 节点的主机级防火墙系统。

它通过 XDP/eBPF 在宿主机网卡入口尽早过滤流量，同时不修改 Kubernetes 已管理的网络规则。

## 语言导航

- English: [`README.md`](README.md)
- 简体中文: `README.zh-CN.md`
- Architecture (EN): [`docs/architecture.md`](docs/architecture.md)
- 架构设计 (ZH-CN): [`docs/architecture.zh-CN.md`](docs/architecture.zh-CN.md)
- 节点鉴权与安全升级：[`docs/security-hardening.zh-CN.md`](docs/security-hardening.zh-CN.md)
- Agent guidelines (EN): [`AGENTS.md`](AGENTS.md)
- Agent 指南 (ZH-CN): [`AGENTS.zh-CN.md`](AGENTS.zh-CN.md)

## 项目目标

- 使用 Go 实现节点 agent 和控制面
- 使用 XDP/eBPF 做早期包过滤
- 只管理宿主机网卡级别的 allowlist
- 不修改 kube-proxy、CNI、iptables 或 nftables 已接管的规则
- 对高风险策略变更加上清晰的回滚路径

## v1 范围

- 仅支持 IPv4 allowlist
- 在指定网卡上 attach/detach XDP
- 基于 LPM trie 的源地址 CIDR 白名单
- 非 IPv4 流量支持 `pass` / `drop` 可配置行为
- 提供本地 agent HTTP API
- 提供轻量控制面 server
- 提供健康检查、计数器和回滚骨架
- 提供单节点最小 Web UI

## 仓库结构

- `cmd/agent`: 本地 NodeWall agent
- `cmd/server`: 控制面 API server
- `internal/xdp`: eBPF 加载、attach 和 map 管理
- `internal/api`: agent/server HTTP handler
- `internal/health`: 健康探针与状态汇总
- `internal/rollback`: 回滚控制
- `internal/store`: 内存存储和本地状态存储
- `bpf/`: XDP 程序与生成辅助文件
- `web/`: 最小浏览器 UI

## 快速开始

1. 生成 eBPF 对象文件：

   ```sh
   make generate
   ```

2. 编译二进制：

   ```sh
   make build
   ```

3. 启动本地完整开发栈：

   ```sh
   make dev
   ```

4. 只运行 agent：

   ```sh
   make run-agent
   ```

5. 只运行 server：

   ```sh
   make run-server
   ```

默认生成的 XDP 对象文件路径为 `bpf/gen/xdpacl_bpfel.o`。

## 构建说明

项目当前对齐主机 Go `1.27.3`。

`make generate` 支持两种方式：

- 在 Linux 主机上直接生成 BPF 对象
- 在 macOS 或其他非 Linux 主机上自动构建 Linux 容器并在容器中生成

容器内已经准备好生成 BPF 所需的基础工具链，例如 `clang`、内核头文件和 `libbpf` 相关头文件。

如果需要覆盖容器镜像或运行时：

```sh
NODEWALL_BPF_IMAGE=my-nodewall-bpf CONTAINER_RUNTIME=docker make generate
```

## 本地开发模式

`make dev` 和 `make dev-demo` 会以 `mock` 数据面模式运行 agent。它适合 macOS、非 Linux 主机以及 UI/API 联调场景。server 会继续直接托管 `web/` 下的静态页面。

`make dev-real` 会走真实数据面路径，面向具备生成好 BPF 对象和足够权限的 Linux 环境。

常用命令：

```sh
make dev
make dev-real
make run-agent
make run-server
```

两种模式的环境变量示例见 `examples/dev.env.example`。

## 多 Web 与节点连通性

多 Web 控制台会区分集群心跳和当前 Web 到 Agent 的通信状态。宿主机上的其他防火墙可能
在 XDP 放行后继续拒绝连接；例如某台机器的 INPUT 白名单只允许原管理端，就会导致备用
Web 无法直连该 Agent。直连 TCP 建连失败时，控制台会尝试通过可达、已登记的其他 Web
中转，沿用节点令牌和已固定的 TLS 证书；最多经过一个中转节点。需要参与中转的 Web
均需更新到包含 `/join/relay` 的版本，并至少保留一条经过认证的可达路径。
请求已经送达后发生的超时或响应丢失不会自动重放写操作。各节点继续管理自己的系统
防火墙；NodeWall 不会为了互联去改写 Docker、CNI 或管理员的 INPUT 规则。
## 旧内核与 ZStack 兼容模式

`iptables` 数据面仅用于无法加载 eBPF/XDP 的非 Kubernetes Linux 主机，例如
使用旧版 CentOS 7 内核的 ZStack KVM 宿主机。它不修改 ZStack 已有规则，而是：

- 为每个受保护网卡在 `filter/INPUT`、`filter/OUTPUT` 中创建独立的 `NWRAW_*`、`NWRAW_OUT_*` 链；链名保留历史前缀以兼容升级和卸载
- 在连接跟踪之后过滤宿主机流量，显式封禁和端口拒绝优先于 `ESTABLISHED,RELATED` 回包放行
- 不挂载 `FORWARD`，虚拟机和容器转发、协议 `253` 的 `zstack-network` NFLOG 仍由原规则处理
- 每 5 秒检查自身跳转、私有链完整内容及规则顺序；链被清空、删除、重排或插入提前放行时会恢复，正常时不会重建链或清零计数
- 升级时移除该网卡旧的 NodeWall `raw`、`mangle` 私有链及引用，不改写 ZStack 规则，也不写入 `/etc/iptables`
- 开启观察模式时只记录命中统计，不安装 `DROP`；策略编译失败时会清空半成品并留下 `RETURN` 兜底

外部规则重写后的恢复受巡检间隔影响，并非零窗口。健康检查会把私有链或跳转漂移报告为异常；
恢复事件会写入 Agent 日志。若要求与其他 root 服务的 iptables 重写完全隔离，应先在维护窗口
验证支持 XDP 的内核及 ZStack、驱动兼容性，再迁移至 XDP 数据面。

安装默认使用 `--dataplane auto`，始终选择 XDP + TC eBPF，不会因为内核版本自动调用
iptables。低于 `4.18` 的内核会在预检阶段明确失败，需要升级内核；只有明确传入
`--dataplane iptables` 才会启用旧内核兼容后端：

```sh
sudo ./bin/nodewall install --dataplane iptables --default-interface em1 --password 'change-me'
```

在 ZStack 桥接网络中，安装参数仍填写物理上联网卡（例如 `em1`）。兼容后端会把
宿主机 INPUT/OUTPUT 入口解析到其 Linux bridge（例如 `br_em1`），不要手动选择 `br_*`、`vnic*`
或 `outer*` 设备。

节点加入脚本会自动把带 IPv4 地址的 ZStack bridge（例如 `br_eno1`）解析为其物理端口
（例如 `eno1`），同时保留 bridge 上的管理地址用于注册。`eno2`、`ens85f0`、`ens85f1`
等其他物理网卡需要在链路恢复后，在节点管理页面逐个挂载；`outer*`、`vnic*` 和内部
bridge 不作为物理防护接口。

加入安装不依赖 systemd 在线：安装器会先校验自己的 systemd unit，systemd 不可连接、
unit 被改动或服务启动失败时，会校验后直接启动独立 Agent，并输出 Agent 日志。该模式
适合被容器化或受损 systemd 环境临时恢复当前运行；主机重启后的自动拉起仍需修复 systemd
或配置受信任的外部进程监督器。

该模式支持入方向的 IPv4 策略、源地址封禁、端口拒绝、受限端口、`hashlimit` 限速、
临时封禁及计数器读取，也支持宿主机本地流量的出方向策略。Kubernetes 节点默认
使用 XDP + TC eBPF 数据面：XDP 在网卡入口过滤，TC eBPF 在网卡出口过滤，不修改 CNI、
kube-proxy 或 ZStack 的 iptables/nftables 规则。内核需要同时允许 BPF/XDP 和 TC 挂载；若
TC 挂载失败，出方向强制发布会失败并保持原策略，不会自动改用 iptables。

## 安装前预检

安装前可以先运行预检命令。预检会检查 Ubuntu 版本、root 权限、Linux 内核、systemd、服务端口、目标网卡、BPF/XDP 和 iptables：

```sh
sudo ./bin/nodewall preflight --default-interface ens18
```

预检会逐项输出 `通过`、`警告`、`失败` 或 `跳过`，只有存在 `失败` 项时才返回失败状态。Ubuntu 最低检查版本为 `18.04`；非 Ubuntu 发行版会给出警告，但仍会继续检查内核和数据面依赖。SSH 日志会优先使用 `/var/log/auth.log` 或 `/var/log/secure`，两者都不存在时自动检查 `journalctl`。`--dataplane auto` 不会启用 iptables；Kubernetes 节点无需额外处理 iptables 兼容规则。

`nodewall install` 会在写入安装目录、配置文件或 systemd unit 之前自动执行同一套预检；预检出现失败项时安装会停止。使用 `--enable-services=false` 时会跳过 systemd 在线状态检查，但其余与当前安装模式相关的检查仍会执行。

## 打包分发

NodeWall 现在支持多架构打包，适合把产物直接分发到目标主机，而不是连同源码仓库一起复制。

默认打包目标：

- `linux/amd64`
- `linux/arm64`

按用途选择打包命令：

```sh
# 仅在尚未生成 BPF 对象时执行
make generate

# 首次离线安装：包含 ClamAV 引擎和完整病毒特征库
make package-offline

# 日常更新：不包含 ClamAV 资源，保留目标节点已有的引擎和数据库
make package-update
```

两个命令都会自动构建前端并编译当前工作区的 Go 代码；前端依赖尚未安装时会根据
`web/package-lock.json` 执行 `npm ci`。每次制作离线包都需要 Docker 和网络，用于检查
`main`、`daily` 和 `bytecode` 病毒库。发现新版时会下载更新并校验三份 CVD 的签名，
ClamAV 引擎及源码缓存通过摘要校验后直接复用。病毒库刷新或验证失败时会中止打包，
保留之前的数据库缓存。`make package-archive` 保留为
`make package-offline` 的兼容别名；`make package` 仍生成不包含 ClamAV 资源的单二进制。

只打一个架构，例如：

```sh
NODEWALL_PACKAGE_TARGETS=linux/amd64 make package-update
```

产物输出到 `dist/`，文件名分别包含 `_offline_linux_amd64.tar.gz` 或
`_update_linux_amd64.tar.gz`（其他架构同理），避免同一版本的两种包相互覆盖。两种包均包含
`nodewall` 二进制和运维说明，离线包额外包含 ClamAV 引擎、完整数据库及其源码说明。

普通更新包不会覆盖或删除目标节点已有的 ClamAV 引擎和数据库。首次离线部署 ClamAV 时，
请使用离线包。集群内任意已注册节点具备离线资源后，其他节点会在启动时及每 2 分钟自动检查、
同步缺失或较旧的 ClamAV 引擎与病毒库，包括最初没有资源的管理节点。入群命令完成后同步在后台
继续，进度和错误可通过 `journalctl -u nodewall-agent -f` 查看，扫描页面也会显示引擎及更新状态。
引擎按版本升级，三份数据库分别选择较新版本，不回退已有版本；引擎升级后自动重启私有 `clamd`。
传输使用已注册节点的凭据及固定 TLS 证书，下载后校验 SHA-256、CVD 签名并测试完整数据库加载，
失败保留原有可用版本。独立节点若没有现成资源、也没有可提供资源的集群节点，普通更新包本身
无法提供离线引擎和病毒库。

在目标 Linux 主机上使用离线包安装：

```sh
tar -xzf nodewall_<version>_offline_linux_amd64.tar.gz
cd nodewall_<version>_offline_linux_amd64
sudo ./bin/nodewall install --password 'change-me'
```

更新已有节点时，解压对应架构的普通更新包，在解压目录执行 `sudo ./bin/nodewall update`。

如果默认的 Web 端口 `8086` 或 Agent 端口 `9080` 已被占用，可在安装时直接改端口：

```sh
sudo ./bin/nodewall install \
  --server-addr 127.0.0.1:18080 \
  --agent-addr 127.0.0.1:19080 \
  --agent-url http://127.0.0.1:19080 \
  --password 'change-me'
```

说明：

- `nodewall install` 会从单二进制中释放运行时资源，不依赖源码仓库
- 新安装的安全 all-in-one 节点在识别到可用 IPv4 地址时，Agent 默认监听 `0.0.0.0:9080`，并向集群通告该地址；显式指定监听地址、关闭 TLS 或无法识别地址时保留相应的原有设置。显式监听 `127.0.0.1` 时，其他管理节点无法直接访问该 Agent。
- 安装只部署服务和页面，不会自动接管默认网卡；需要在控制台显式启用防护
- `nodewall cleanup` 必须以 root 执行；它会先停止 NodeWall 进程，恢复 NodeWall 修改过的 `sshd` 配置、SFTP 子系统和 root 控制台公钥，再删除运行文件。SSH 恢复校验或重载失败时会停止并保留恢复文件，不会删除二进制，便于从本地控制台重试。
- 卸载前如果管理员正在维护 `/root/.ssh/authorized_keys`，清理只删除带有 `nodewall-console` 标记且由 NodeWall 写入的公钥，保留其他新增密钥；若安装目录中有未知文件，清理会拒绝删除并报告路径。
- 安装前会先检查目标端口是否可用，再写入 `/etc/nodewall/nodewall.env`；主节点和加入集群的备用管理节点统一从 `8086` 开始选择 Web 端口，升级或重新注册时，旧的 `8080` 至 `8085` 配置也会迁移到 `8086` 之后，并在节点心跳中上报实际管理 Web 地址
- 如果安装后还需要改端口，可修改 `/etc/nodewall/nodewall.env`，再重启服务
- 打包前需要已有 `bpf/gen/xdpacl_bpfel.o`，也就是先执行 `make generate`

如果旧版本卸载已经删除了 `/opt/nodewall/bin/nodewall`，但 SSH 仍命中旧的
NodeWall `ForceCommand`，请先从本地控制台执行以下恢复步骤；不要先删除
`/etc/nodewall`，因为其中可能还有 SFTP 原始配置状态：

```sh
sudo cp -a /etc/ssh/sshd_config "/etc/ssh/sshd_config.nodewall-recovery.$(date +%s)"
sudo sed -i '/^# BEGIN NODEWALL SSH POLICY$/,/^# END NODEWALL SSH POLICY$/d' /etc/ssh/sshd_config
sudo sshd -t -f /etc/ssh/sshd_config
sudo systemctl reload sshd || sudo systemctl reload ssh
```

确认 SSH 登录恢复后，再使用新版本二进制执行 `nodewall uninstall`；如果
`Subsystem sftp` 仍指向 `nodewall-sftp-deny`，先根据备份或
`/etc/nodewall/ssh-transfer-state.json` 恢复原来的 `Subsystem sftp` 行。

## 智能网卡识别

agent 现在支持自动发现宿主机网卡，并给出一个推荐网卡候选，依据包括：

- 网卡是否处于 up 状态
- 是否为 loopback
- 是否拥有地址
- 是否像物理网卡命名

相关入口：

- Agent API: `GET /interfaces`
- Server 代理: `GET /nodes/{node}/interfaces`
- Web UI: 支持一键识别并套用推荐网卡

同时仍然保留手工输入网卡名的能力。

## 重启恢复

agent 现在会持久化网卡运行时状态，并在启动时自动重放恢复。

- 持久化文件由 `NODEWALL_AGENT_STATE` 指定
- Linux 安装部署默认使用 `/etc/nodewall/agent-state.json`
- 重启后会重新加载已附着网卡、重新写回 allowlist，以及恢复非 IPv4 动作配置
- 对未完成确认的发布任务，会保守地标记为失败，而不是在丢失原始回滚窗口的情况下继续恢复

这意味着系统重启或 agent 异常退出后，不再只是“保留元数据”，而是会主动恢复数据面状态。

## 流量与攻击分析

NodeWall 现在支持按来源 IP 提供放行/丢弃分析能力。

- XDP 数据面会在 `source_stats` map 中记录来源 IP 的 pass/drop 计数
- Agent API: `GET /interfaces/{iface}/insights`
- Server 代理: `GET /nodes/{node}/interfaces/{iface}/insights`
- Web UI: 展示高风险来源和主要放行来源的简单图表

当前“攻击风险”属于启发式分析，主要依据丢弃量和丢弃比例，目标是给运维提供快速观察入口，而不是替代完整的安全分析平台。

UI 还会保留一段最近的 pass/drop 趋势快照，并针对高风险丢弃来源给出少量 `/32` 封禁建议。

## 一键部署与一键清理

NodeWall 现在提供面向 Linux 的运维脚本：

- `make deploy`: 编译二进制、安装文件、写入默认 env、启用并启动 `nodewall-agent.service` 与 `nodewall-server.service`
- `make cleanup`: 在 Linux root 环境下停止并禁用已安装服务、删除安装目录和配置目录，并清理本地构建产物

systemd 服务定义位于 `deployments/systemd/`，并支持通过 `/etc/nodewall/nodewall.env` 覆盖默认环境变量。
如果默认的 `0.0.0.0:8086` 或 `127.0.0.1:9080` 已占用，可以在该文件里调整
`NODEWALL_SERVER_ADDR`、`NODEWALL_AGENT_ADDR` 和 `NODEWALL_AGENT_URL` 后再重启服务。

## 访问白名单与登录密码

生产部署现在支持以下 Web 控制台保护能力：

- server 侧登录密码
- 通过 `NODEWALL_ALLOWED_CIDRS` 配置基于 CIDR 的访问白名单
- 通过 `NODEWALL_ALLOWED_IPS` 直接配置单个 IP 白名单
- 通过 `NODEWALL_ALLOWED_MACS` 配置基于 MAC 的访问白名单
- `NODEWALL_WEB_ACCESS=public`（默认）允许外部访问，仍然需要登录；只有显式设置
  `NODEWALL_WEB_ACCESS=restricted` 或 `allowlist` 时才会启用上述来源白名单。
- `NODEWALL_WEB_ACCESS=drop` 仅允许本机回环访问，适合临时维护。

集群互联基线会自动保留管理端 TCP `8082`，并在新节点加入或管理端重启时补齐到已有节点的策略。已有策略处于观察模式时只写入规则，不会自动开始拦截；页面可以选择永久启用，或先按 `1` 至 `120` 秒试运行。试运行期间如果页面没有确认保持开启，Agent 会在超时后自动恢复到试运行前的状态，适合 ZStack 等管理链路不能中断的主机。

节点管理页面每个节点都提供“同步更新 Agent”操作。它会通过节点凭证立即触发目标节点从当前管理端下载并安装版本，完成后由 Agent 重启自身服务；加入集群后的正常心跳仍会继续检查版本差异。删除节点时页面会带上强制清理标记，即使最近心跳已过期，只要 Agent 仍可访问，也会先卸载防护并触发 Agent 自删除，再从管理端撤销节点凭证和本地策略。

其中 MAC 白名单依赖主机能够解析访问来源的邻居表记录。

如果只是放行单个来源，现在可以直接写：

```sh
NODEWALL_ALLOWED_IPS=192.168.1.10,192.168.1.11
```

不需要手动把每个 IP 换算成 `/32`。

`make dev` 默认关闭登录校验，方便本地开发。

密码文件：

- 默认路径：`/etc/nodewall/auth.json`
- 部署时自动生成
- 后续可通过主机命令修改：

```sh
/opt/nodewall/bin/nodewall set-password --file /etc/nodewall/auth.json
```

## 安全原则

NodeWall 在实现上刻意保持保守：

- 高风险策略变更总是包裹在回滚会话里
- 非 IPv4 行为必须显式配置
- 健康检查会作为 apply 后的门槛
- 必须保留手动恢复路径
