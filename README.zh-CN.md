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

## 旧内核与 ZStack 兼容模式

`iptables` 数据面仅用于无法加载 eBPF/XDP 的非 Kubernetes Linux 主机，例如
使用旧版 CentOS 7 内核的 ZStack KVM 宿主机。它不修改 ZStack 已有规则，而是：

- 为每个受保护网卡创建独立的 `NWRAW_*` 入方向链，以及 `NWRAW_OUT_*`、`NWFW_OUT_*` 出方向链
- 将自身跳转恢复到 `raw/PREROUTING` 顶部，避免被 ZStack 的 catch-all 规则跳过
- 始终让 IP 协议 `253` 返回至 ZStack 自己的 `zstack-network` NFLOG 规则
- 每 5 秒检查一次跳转位置；ZStack 网络代理重建 raw 链后会自动恢复
- 出方向策略同时覆盖 `raw/OUTPUT` 的宿主机本地流量和 `mangle/FORWARD` 的桥接转发流量，不会覆盖入方向规则
- 开启观察模式时只记录命中统计，不安装 `DROP`；策略编译失败时会清空半成品并留下 `RETURN` 兜底

安装默认使用 `--dataplane auto`：内核低于 `4.18`（包括 CentOS 7 的 `3.10`）会自动选择
`iptables`，更高版本仍使用 XDP。也可以明确选择该模式：

```sh
sudo ./bin/nodewall install --dataplane iptables --default-interface em1 --password 'change-me'
```

在 ZStack 桥接网络中，安装参数仍填写物理上联网卡（例如 `em1`）。兼容后端会把
raw 表入口解析到其 Linux bridge（例如 `br_em1`），不要手动选择 `br_*`、`vnic*`
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
临时封禁及计数器读取，也支持宿主机本地和桥接转发流量的出方向策略。它不能用于 Kubernetes
节点；Kubernetes 场景必须继续使用 XDP 数据面，避免与 kube-proxy、CNI 的 netfilter
规则冲突。原生 XDP 的出方向仍是连接跟踪和观察能力，若需要出方向强制拦截，请选择
`iptables` 数据面。

## 安装前预检

安装前可以先运行预检命令。预检会检查 Ubuntu 版本、root 权限、Linux 内核、systemd、服务端口、目标网卡、BPF/XDP 和 iptables：

```sh
sudo ./bin/nodewall preflight --default-interface ens18
```

预检会逐项输出 `通过`、`警告`、`失败` 或 `跳过`，只有存在 `失败` 项时才返回失败状态。Ubuntu 最低检查版本为 `18.04`；非 Ubuntu 发行版会给出警告，但仍会继续检查内核和数据面依赖。SSH 日志会优先使用 `/var/log/auth.log` 或 `/var/log/secure`，两者都不存在时自动检查 `journalctl`。`--dataplane auto` 会按内核版本选择 XDP 或 iptables，Kubernetes 节点应确保最终选择 XDP。

`nodewall install` 会在写入安装目录、配置文件或 systemd unit 之前自动执行同一套预检；预检出现失败项时安装会停止。使用 `--enable-services=false` 时会跳过 systemd 在线状态检查，但其余与当前安装模式相关的检查仍会执行。

## 打包分发

NodeWall 现在支持多架构打包，适合把产物直接分发到目标主机，而不是连同源码仓库一起复制。

默认打包目标：

- `linux/amd64`
- `linux/arm64`

执行打包：

```sh
make generate
make package-archive
```

`make package-archive` 会自动执行前端构建，再编译当前工作区的 Go 代码并生成归档，
不需要先手动执行 `npm --prefix web run build`。如果前端依赖尚未安装，脚本会根据
`web/package-lock.json` 自动执行 `npm ci`。

只打一个目标：

```sh
make package-one TARGET=linux/amd64
```

产物会输出到 `dist/` 目录，格式为 `.tar.gz`。每个压缩包内包含：

- 预编译的 `nodewall`
- README 与运维说明

在目标 Linux 主机上可直接执行：

```sh
tar -xzf nodewall_<version>_linux_amd64.tar.gz
cd nodewall_<version>_linux_amd64
sudo ./bin/nodewall install --password 'change-me'
sudo ./bin/nodewall cleanup
```

如果默认的 `0.0.0.0:8080` 或 `127.0.0.1:9080` 已被占用，可在安装时直接改端口：

```sh
sudo ./bin/nodewall install \
  --server-addr 127.0.0.1:18080 \
  --agent-addr 127.0.0.1:19080 \
  --agent-url http://127.0.0.1:19080 \
  --password 'change-me'
```

说明：

- `nodewall install` 会从单二进制中释放运行时资源，不依赖源码仓库
- 安装只部署服务和页面，不会自动接管默认网卡；需要在控制台显式启用防护
- `nodewall cleanup` 负责卸载已安装内容
- 安装前会先检查目标端口是否可用，再写入 `/etc/nodewall/nodewall.env`
- 如果安装后还需要改端口，可修改 `/etc/nodewall/nodewall.env`，再重启服务
- 打包前需要已有 `bpf/gen/xdpacl_bpfel.o`，也就是先执行 `make generate`

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
如果默认的 `0.0.0.0:8080` 或 `127.0.0.1:9080` 已占用，可以在该文件里调整
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
