# NodeWall 架构设计

## 概览

NodeWall 是一个面向 Kubernetes 节点的主机级防火墙系统。

它在宿主机网卡入口使用 XDP/eBPF 进行流量过滤，同时避免修改 Kubernetes 已管理的 netfilter 状态。

## 核心组件

- Web UI
- Go API Server
- Go Node Agent
- 挂载到目标网卡上的 XDP 程序
- 用于 allowlist、计数器和配置的 BPF maps

## 报文路径

```text
NIC -> XDP -> kernel networking stack -> kube-proxy / CNI / netfilter
```

NodeWall 只在 XDP 层工作。

## 数据面逻辑

v1 的 XDP 程序流程：

1. 解析 Ethernet 头
2. 判断是否为 IPv4 流量
3. 对非 IPv4 流量执行可配置动作
4. 读取 IPv4 源地址
5. 在 LPM trie allowlist 中查找
6. 命中则放行，未命中则丢弃
7. 更新 pass/drop 计数器

## 控制面

### Node Agent

负责：

- 加载 XDP 对象
- attach / detach 程序
- 更新 BPF maps
- 上报计数器
- 执行本地健康检查
- 管理回滚会话

### API Server

负责：

- 存储网卡策略
- 记录发布历史
- 驱动单节点 publish 和 rollback
- 托管最小 Web UI

## 回滚模型

Apply 流程：

1. 快照当前状态
2. 应用新策略
3. 执行健康检查
4. 打开确认窗口
5. 用户确认或自动回滚

## 默认安全约束

- IPv4 流量采用 allowlist 模式
- 非 IPv4 动作必须显式
- 健康检查决定变更是否完成
- 必须始终保留恢复路径
