# NodeWall 打包产物使用说明

这个压缩包只用于部署，不包含源码开发说明。

## 包内内容

- `bin/nodewall`：统一运行与运维二进制

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

默认情况下：

- Web 服务监听 `0.0.0.0:8080`，局域网其他设备可以访问
- agent 监听 `127.0.0.1:9080`
- 拦截日志写入 `/var/lib/nodewall/logs`
- 日志状态保存到 `/etc/nodewall/drop-log-state.json`
- 默认保留 `7` 天，每 `30` 秒刷盘一次

## ZStack 旧内核兼容模式

安装默认会根据内核自动选择数据面：内核低于 `4.18`（包括 CentOS 7 的 `3.10`）使用
iptables 兼容模式；也可以明确指定：

```sh
sudo ./bin/nodewall install \
  --dataplane iptables \
  --default-interface em1 \
  --password 'change-me'
```

该模式仅面向非 Kubernetes 的 ZStack/CentOS 主机。它在 raw 表中维护独立
`NWRAW_*` 链，不删除 ZStack 规则，并保留协议 `253` 的 ZStack 网络日志路径。
出方向会额外维护 `NWRAW_OUT_*`、`NWFW_OUT_*` 链，分别覆盖宿主机本地 `raw/OUTPUT` 和
桥接转发 `mangle/FORWARD` 流量；观察模式不会安装 `DROP` 规则。不要将 bridge、`vnic*`、`outer*` 等虚拟接口作为 `--default-interface`
参数。Kubernetes 节点不要使用该模式，以免与 CNI 和 kube-proxy 的规则边界冲突。

远程加入时，脚本会把 ZStack bridge（例如 `br_eno1`）解析为物理端口（例如 `eno1`），
并保留 bridge 上的管理地址。其他物理网卡可在链路恢复后从节点管理页面逐个挂载。
如果 systemd 不可用或 unit 校验失败，脚本会校验后直接启动 Agent，并将日志写入
`/var/log/nodewall/agent.log`；恢复重启后的自动启动仍需修复 systemd 或配置外部监督器。

集群基线默认保留管理端 TCP `8082`，新节点加入和管理端重启时会自动补齐已有节点的互联规则。
新节点不会因为加入就立即开启拦截；可在页面永久启用，或先选择 `1` 至 `120` 秒试运行。
试运行未确认时会自动恢复到试运行前状态，避免 ZStack 管理链路被误断。

## 修改密码

```sh
sudo /opt/nodewall/bin/nodewall set-password --file /etc/nodewall/auth.json --password 'new-password'
```

## 更新

把新的压缩包解压后，直接在新目录里执行：

```sh
sudo ./bin/nodewall update
```

更新会保留现有配置、密码和端口，只覆盖：

- `/opt/nodewall/bin/nodewall`
- `/opt/nodewall/web`
- `/opt/nodewall/bpf/gen/xdpacl_bpfel.o`
- systemd unit 文件

默认会对正在运行的服务执行就地重启。如果你只想先替换文件，不立刻重启：

```sh
sudo ./bin/nodewall update --restart-services=false
```

## 端口冲突处理

如果默认端口被占用，安装器会自动顺延到下一个空闲端口。比如 `8080` 被占用时，会继续尝试 `8081`、`8082`。

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
