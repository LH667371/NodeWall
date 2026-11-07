# AGENTS.zh-CN.md

## 项目目标

构建一个面向生产的单节点 MVP，用于 Kubernetes 节点的主机级防火墙系统。

## 核心约束

- 控制面和节点 agent 使用 Go
- 数据面使用 C 编写的 XDP/eBPF
- eBPF 代码保持最小化且易审计
- 只管理宿主机网卡级别 allowlist
- 不修改 Kubernetes 管理的 iptables、nftables、kube-proxy 或 CNI 规则

## v1 范围

- 按网卡维度管理 IPv4 allowlist
- 未命中的 IPv4 默认拒绝
- 非 IPv4 动作可配置
- 支持按需 attach/detach XDP
- 通过 BPF maps 热更新
- 提供计数器、健康检查、回滚和简单 Web UI

## 编码规则

- 能用标准库时优先标准库
- 包边界尽量清晰且小
- 高风险操作必须返回可执行的错误信息
- 为解析、回滚和 handler 补聚焦测试
- 任何策略 apply 路径都必须保留恢复路径

## 推荐交付顺序

1. 仓库骨架和文档
2. 最小 XDP 程序
3. Go loader 与 map 管理
4. 本地 Node Agent API
5. 回滚与健康检查
6. 中央 server
7. 最小 Web UI
