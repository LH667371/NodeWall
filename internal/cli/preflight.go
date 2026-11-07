package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	assets "nodewall"
	"nodewall/internal/models"
	"nodewall/internal/xdp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	preflightPass      = "通过"
	preflightWarn      = "警告"
	preflightFail      = "失败"
	preflightSkip      = "跳过"
	minimumUbuntuMajor = 18
	minimumUbuntuMinor = 4
)

type preflightCheck struct {
	Name   string
	Status string
	Detail string
}

type preflightReport struct {
	Checks    []preflightCheck
	Dataplane string
}

func (r preflightReport) failed() bool {
	for _, check := range r.Checks {
		if check.Status == preflightFail {
			return true
		}
	}
	return false
}

func (r preflightReport) warningCount() int {
	count := 0
	for _, check := range r.Checks {
		if check.Status == preflightWarn {
			count++
		}
	}
	return count
}

func (r preflightReport) failureSummary() string {
	items := make([]string, 0)
	for _, check := range r.Checks {
		if check.Status == preflightFail {
			items = append(items, check.Name+": "+check.Detail)
		}
	}
	return strings.Join(items, "; ")
}

func (r preflightReport) render(w io.Writer) {
	fmt.Fprintln(w, "NodeWall 安装预检")
	if r.Dataplane != "" {
		fmt.Fprintf(w, "数据面: %s\n", r.Dataplane)
	}
	for _, check := range r.Checks {
		fmt.Fprintf(w, "[%s] %-10s %s\n", check.Status, check.Name, check.Detail)
	}
	switch {
	case r.failed():
		fmt.Fprintf(w, "结论: 不可安装；请先修复失败项。\n")
	case r.warningCount() > 0:
		fmt.Fprintf(w, "结论: 可以安装，但存在 %d 个警告。\n", r.warningCount())
	default:
		fmt.Fprintln(w, "结论: 可以安装。")
	}
}

type preflightOptions struct {
	Dataplane          string
	RequestedDataplane string
	InstallMode        string
	EnableServices     bool
	DefaultInterface   string
	AgentAddr          string
	ServerAddr         string
	ServerGRPCAddr     string
	ServerQUICAddr     string
	AllowPortReuse     bool
	BPFObject          []byte
}

// preflightDeps keeps host probes injectable. The production path uses the
// real operating-system calls, while unit tests can exercise the decision
// logic without requiring an Ubuntu host, systemd, or BPF privileges.
type preflightDeps struct {
	goos               string
	euid               func() int
	readFile           func(string) ([]byte, error)
	stat               func(string) (os.FileInfo, error)
	lookPath           func(string) (string, error)
	runCommand         func(string, ...string) (string, error)
	discoverInterfaces func() (models.InterfaceInventory, error)
	listenTCP          func(string, string) (net.Listener, error)
	listenUDP          func(string, string) (net.PacketConn, error)
	probeBPF           func([]byte) error
}

func defaultPreflightDeps() preflightDeps {
	return preflightDeps{
		goos:               runtime.GOOS,
		euid:               os.Geteuid,
		readFile:           os.ReadFile,
		stat:               os.Stat,
		lookPath:           exec.LookPath,
		runCommand:         runPreflightCommand,
		discoverInterfaces: xdp.DetectHostInterfaces,
		listenTCP:          net.Listen,
		listenUDP:          net.ListenPacket,
		probeBPF:           probeBPFObject,
	}
}

func runPreflightCommand(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func runPreflight(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	dataplane := fs.String("dataplane", envOr("NODEWALL_DATAPLANE", "auto"), "数据面：auto|real|iptables")
	installMode := fs.String("mode", envOr("NODEWALL_INSTALL_MODE", "all-in-one"), "安装模式：all-in-one|server-only|agent-only")
	enableServices := fs.Bool("enable-services", envBool("NODEWALL_ENABLE_SERVICES", true), "检查 systemd 服务能力")
	defaultInterface := fs.String("default-interface", envOr("NODEWALL_DEFAULT_INTERFACE", ""), "待保护网卡，留空自动探测")
	agentAddr := fs.String("agent-addr", envOr("NODEWALL_AGENT_ADDR", "127.0.0.1:9080"), "Agent 监听地址")
	serverAddr := fs.String("server-addr", envOr("NODEWALL_SERVER_ADDR", "0.0.0.0:8080"), "Web Server 监听地址")
	serverGRPCAddr := fs.String("server-grpc-addr", envOr("NODEWALL_SERVER_GRPC_ADDR", "0.0.0.0:50051"), "gRPC 监听地址，留空禁用")
	serverQUICAddr := fs.String("server-quic-addr", envOr("NODEWALL_SERVER_QUIC_ADDR", "0.0.0.0:50052"), "QUIC 监听地址，留空禁用")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mode, err := normalizeInstallMode(*installMode)
	if err != nil {
		return err
	}
	resolvedDataplane, err := resolveInstallDataplane(*dataplane)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*defaultInterface) == "" {
		*defaultInterface = detectDefaultInterface()
	}
	resolvedAgentAddr := strings.TrimSpace(*agentAddr)
	resolvedServerAddr := strings.TrimSpace(*serverAddr)
	if mode == "all-in-one" || mode == "agent-only" {
		resolvedAgentAddr, _, err = chooseAvailableTCPAddr(resolvedAgentAddr)
		if err != nil {
			return fmt.Errorf("choose agent address: %w", err)
		}
	}
	if mode == "all-in-one" || mode == "server-only" {
		resolvedServerAddr, _, err = chooseAvailableTCPAddr(resolvedServerAddr)
		if err != nil {
			return fmt.Errorf("choose server address: %w", err)
		}
	}

	object, objectErr := assets.ReadFile("bpf/gen/xdpacl_bpfel.o")
	if objectErr != nil {
		object = nil
	}
	report := checkPreflight(preflightOptions{
		Dataplane:          resolvedDataplane,
		RequestedDataplane: strings.TrimSpace(*dataplane),
		InstallMode:        mode,
		EnableServices:     *enableServices,
		DefaultInterface:   strings.TrimSpace(*defaultInterface),
		AgentAddr:          resolvedAgentAddr,
		ServerAddr:         resolvedServerAddr,
		ServerGRPCAddr:     strings.TrimSpace(*serverGRPCAddr),
		ServerQUICAddr:     strings.TrimSpace(*serverQUICAddr),
		BPFObject:          object,
	}, defaultPreflightDeps())
	report.render(os.Stdout)
	if report.failed() {
		return fmt.Errorf("preflight failed: %s", report.failureSummary())
	}
	return nil
}

func normalizeInstallMode(value string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(value))
	if mode == "" {
		mode = "all-in-one"
	}
	if mode != "all-in-one" && mode != "server-only" && mode != "agent-only" {
		return "", fmt.Errorf("invalid install mode %q, expected all-in-one|server-only|agent-only", value)
	}
	return mode, nil
}

func checkPreflight(opts preflightOptions, deps preflightDeps) preflightReport {
	if deps.goos == "" {
		deps.goos = runtime.GOOS
	}
	if deps.euid == nil {
		deps.euid = os.Geteuid
	}
	if deps.readFile == nil {
		deps.readFile = os.ReadFile
	}
	if deps.stat == nil {
		deps.stat = os.Stat
	}
	if deps.lookPath == nil {
		deps.lookPath = exec.LookPath
	}
	if deps.runCommand == nil {
		deps.runCommand = runPreflightCommand
	}
	if deps.discoverInterfaces == nil {
		deps.discoverInterfaces = xdp.DetectHostInterfaces
	}
	if deps.listenTCP == nil {
		deps.listenTCP = net.Listen
	}
	if deps.listenUDP == nil {
		deps.listenUDP = net.ListenPacket
	}
	if deps.probeBPF == nil {
		deps.probeBPF = probeBPFObject
	}

	dataplane := opts.Dataplane
	if requested := strings.TrimSpace(opts.RequestedDataplane); requested != "" && requested != opts.Dataplane {
		dataplane = requested + " -> " + opts.Dataplane
	}
	report := preflightReport{Dataplane: dataplane}
	report.Checks = append(report.Checks,
		checkUbuntu(deps),
		checkPermission(deps),
		checkKernel(opts, deps),
		checkSystemd(opts, deps),
		checkPorts(opts, deps),
		checkInterface(opts, deps),
		checkBPFXDP(opts, deps),
		checkIPTables(opts, deps),
		checkSSHLogSource(opts, deps),
	)
	return report
}

func checkUbuntu(deps preflightDeps) preflightCheck {
	data, err := deps.readFile("/etc/os-release")
	if err != nil {
		return preflightCheck{Name: "Ubuntu 版本", Status: preflightFail, Detail: fmt.Sprintf("无法读取 /etc/os-release: %v", err)}
	}
	values := parseOSRelease(data)
	id := strings.ToLower(values["ID"])
	version := values["VERSION_ID"]
	if id != "ubuntu" {
		if id == "" {
			return preflightCheck{Name: "Ubuntu 版本", Status: preflightFail, Detail: "未识别到 Linux 发行版 ID"}
		}
		return preflightCheck{Name: "Ubuntu 版本", Status: preflightWarn, Detail: fmt.Sprintf("当前为 %s %s；项目未对该发行版做 Ubuntu 版本承诺", id, version)}
	}
	major, minor, ok := parseUbuntuVersion(version)
	if !ok {
		return preflightCheck{Name: "Ubuntu 版本", Status: preflightFail, Detail: fmt.Sprintf("VERSION_ID=%q 无法解析", version)}
	}
	if major < minimumUbuntuMajor || (major == minimumUbuntuMajor && minor < minimumUbuntuMinor) {
		return preflightCheck{Name: "Ubuntu 版本", Status: preflightFail, Detail: fmt.Sprintf("Ubuntu %d.%02d 低于最低支持版本 18.04", major, minor)}
	}
	detail := "Ubuntu " + version
	if codename := strings.TrimSpace(values["VERSION_CODENAME"]); codename != "" {
		detail += " (" + codename + ")"
	}
	return preflightCheck{Name: "Ubuntu 版本", Status: preflightPass, Detail: detail}
}

func parseOSRelease(data []byte) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, "\"")
		value = strings.Trim(value, "'")
		values[key] = value
	}
	return values
}

func parseUbuntuVersion(value string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minorText := parts[1]
	if len(minorText) > 2 {
		minorText = minorText[:2]
	}
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func checkPermission(deps preflightDeps) preflightCheck {
	if deps.euid() != 0 {
		return preflightCheck{Name: "权限", Status: preflightFail, Detail: "必须使用 root 运行；请使用 sudo"}
	}
	return preflightCheck{Name: "权限", Status: preflightPass, Detail: "当前用户为 root，可检查 BPF/XDP 和 iptables"}
}

func checkKernel(opts preflightOptions, deps preflightDeps) preflightCheck {
	if opts.InstallMode == "server-only" {
		return preflightCheck{Name: "Linux 内核", Status: preflightSkip, Detail: "server-only 模式不运行本机数据面"}
	}
	data, err := deps.readFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return preflightCheck{Name: "Linux 内核", Status: preflightFail, Detail: fmt.Sprintf("无法读取内核版本: %v", err)}
	}
	release := strings.TrimSpace(string(data))
	major, minor, ok := parseKernelRelease(release)
	if !ok {
		return preflightCheck{Name: "Linux 内核", Status: preflightFail, Detail: fmt.Sprintf("无法解析内核版本 %q", release)}
	}
	if opts.Dataplane == "real" && (major < 4 || (major == 4 && minor < 18)) {
		return preflightCheck{Name: "Linux 内核", Status: preflightFail, Detail: fmt.Sprintf("%s 低于 XDP/eBPF 所需的 4.18；请使用 iptables 或升级内核", release)}
	}
	if opts.Dataplane == "iptables" && (major < 4 || (major == 4 && minor < 18)) {
		return preflightCheck{Name: "Linux 内核", Status: preflightPass, Detail: fmt.Sprintf("%s；将使用旧内核 iptables 兼容数据面", release)}
	}
	return preflightCheck{Name: "Linux 内核", Status: preflightPass, Detail: fmt.Sprintf("%s；数据面=%s", release, opts.Dataplane)}
}

func parseKernelRelease(release string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(release), ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, ok := parseKernelVersionPart(parts[0])
	if !ok {
		return 0, 0, false
	}
	minor, ok := parseKernelVersionPart(parts[1])
	if !ok {
		return 0, 0, false
	}
	return major, minor, true
}

func checkSystemd(opts preflightOptions, deps preflightDeps) preflightCheck {
	if !opts.EnableServices {
		return preflightCheck{Name: "systemd", Status: preflightSkip, Detail: "--enable-services=false，不要求 systemd 在线"}
	}
	if deps.goos != "linux" {
		return preflightCheck{Name: "systemd", Status: preflightFail, Detail: "systemd 服务只能在 Linux 主机上启用"}
	}
	if _, err := deps.lookPath("systemctl"); err != nil {
		return preflightCheck{Name: "systemd", Status: preflightFail, Detail: fmt.Sprintf("找不到 systemctl: %v", err)}
	}
	state, err := deps.runCommand("systemctl", "show", "--property=SystemState", "--value")
	state = strings.TrimSpace(state)
	if err != nil || state == "" || state == "offline" || state == "unknown" {
		if err != nil {
			return preflightCheck{Name: "systemd", Status: preflightFail, Detail: fmt.Sprintf("systemd 未运行或不可连接: %v", err)}
		}
		return preflightCheck{Name: "systemd", Status: preflightFail, Detail: fmt.Sprintf("systemd 状态为 %q", state)}
	}
	return preflightCheck{Name: "systemd", Status: preflightPass, Detail: "systemctl 可用，状态=" + state}
}

type preflightPort struct {
	Name    string
	Network string
	Address string
}

func checkPorts(opts preflightOptions, deps preflightDeps) preflightCheck {
	targets := make([]preflightPort, 0, 4)
	switch opts.InstallMode {
	case "all-in-one", "agent-only":
		targets = append(targets, preflightPort{Name: "agent", Network: "tcp", Address: opts.AgentAddr})
	}
	switch opts.InstallMode {
	case "all-in-one", "server-only":
		targets = append(targets, preflightPort{Name: "server", Network: "tcp", Address: opts.ServerAddr})
		if strings.TrimSpace(opts.ServerGRPCAddr) != "" {
			targets = append(targets, preflightPort{Name: "server-gRPC", Network: "tcp", Address: opts.ServerGRPCAddr})
		}
		if strings.TrimSpace(opts.ServerQUICAddr) != "" {
			targets = append(targets, preflightPort{Name: "server-QUIC", Network: "udp", Address: opts.ServerQUICAddr})
		}
	}
	if len(targets) == 0 {
		return preflightCheck{Name: "端口", Status: preflightFail, Detail: "没有可检查的服务监听地址"}
	}

	var tcpListeners []net.Listener
	var udpListeners []net.PacketConn
	defer func() {
		for _, listener := range tcpListeners {
			_ = listener.Close()
		}
		for _, listener := range udpListeners {
			_ = listener.Close()
		}
	}()
	failed := make([]string, 0)
	warnings := make([]string, 0)
	for _, target := range targets {
		address := strings.TrimSpace(target.Address)
		if address == "" {
			failed = append(failed, target.Name+" 地址为空")
			continue
		}
		if target.Network == "udp" {
			listener, err := deps.listenUDP(target.Network, address)
			if err != nil {
				if opts.AllowPortReuse && target.Name == "agent" {
					warnings = append(warnings, fmt.Sprintf("%s %s 当前已被现有 Agent 占用，将在重注册时复用", target.Name, address))
				} else {
					failed = append(failed, fmt.Sprintf("%s %s 不可用: %v", target.Name, address, err))
				}
				continue
			}
			udpListeners = append(udpListeners, listener)
			continue
		}
		listener, err := deps.listenTCP(target.Network, address)
		if err != nil {
			if opts.AllowPortReuse && target.Name == "agent" {
				warnings = append(warnings, fmt.Sprintf("%s %s 当前已被现有 Agent 占用，将在重注册时复用", target.Name, address))
			} else {
				failed = append(failed, fmt.Sprintf("%s %s 不可用: %v", target.Name, address, err))
			}
			continue
		}
		tcpListeners = append(tcpListeners, listener)
	}
	if len(failed) > 0 {
		return preflightCheck{Name: "端口", Status: preflightFail, Detail: strings.Join(failed, "; ")}
	}
	addresses := make([]string, 0, len(targets))
	for _, target := range targets {
		addresses = append(addresses, target.Name+"="+target.Address)
	}
	if len(warnings) > 0 {
		return preflightCheck{Name: "端口", Status: preflightWarn, Detail: strings.Join(warnings, "; ")}
	}
	return preflightCheck{Name: "端口", Status: preflightPass, Detail: strings.Join(addresses, ", ") + " 均可监听"}
}

func checkInterface(opts preflightOptions, deps preflightDeps) preflightCheck {
	if opts.InstallMode == "server-only" {
		return preflightCheck{Name: "网卡", Status: preflightSkip, Detail: "server-only 模式不运行本机 Agent"}
	}
	inventory, err := deps.discoverInterfaces()
	if err != nil {
		return preflightCheck{Name: "网卡", Status: preflightFail, Detail: fmt.Sprintf("无法读取网卡列表: %v", err)}
	}
	name := strings.TrimSpace(opts.DefaultInterface)
	if name == "" {
		name = strings.TrimSpace(inventory.Recommended)
	}
	if name == "" {
		return preflightCheck{Name: "网卡", Status: preflightFail, Detail: "没有发现可用的推荐网卡"}
	}
	for _, item := range inventory.Interfaces {
		if item.Name != name {
			continue
		}
		if item.IsLoopback {
			return preflightCheck{Name: "网卡", Status: preflightFail, Detail: fmt.Sprintf("%s 是 loopback 网卡，不能挂载防护", name)}
		}
		if !item.IsPhysical {
			return preflightCheck{Name: "网卡", Status: preflightFail, Detail: fmt.Sprintf("%s 不是可挂载的物理网卡", name)}
		}
		if !item.IsUp {
			return preflightCheck{Name: "网卡", Status: preflightFail, Detail: fmt.Sprintf("%s 当前未处于 up 状态", name)}
		}
		detail := fmt.Sprintf("%s 可用，MTU=%d", name, item.MTU)
		if len(item.Addresses) == 0 {
			return preflightCheck{Name: "网卡", Status: preflightWarn, Detail: detail + "，尚未配置地址"}
		}
		return preflightCheck{Name: "网卡", Status: preflightPass, Detail: detail + "，地址=" + strings.Join(item.Addresses, ",")}
	}
	return preflightCheck{Name: "网卡", Status: preflightFail, Detail: fmt.Sprintf("找不到网卡 %q", name)}
}

func checkBPFXDP(opts preflightOptions, deps preflightDeps) preflightCheck {
	if opts.InstallMode == "server-only" {
		return preflightCheck{Name: "BPF/XDP", Status: preflightSkip, Detail: "server-only 模式不运行本机 Agent"}
	}
	if opts.Dataplane != "real" {
		return preflightCheck{Name: "BPF/XDP", Status: preflightSkip, Detail: "当前数据面为 iptables，不需要加载 XDP/eBPF"}
	}
	if deps.goos != "linux" {
		return preflightCheck{Name: "BPF/XDP", Status: preflightFail, Detail: "XDP/eBPF 数据面只能在 Linux 上运行"}
	}
	if deps.euid() != 0 {
		return preflightCheck{Name: "BPF/XDP", Status: preflightFail, Detail: "加载 BPF 程序需要 root 或相应 capability"}
	}
	if len(opts.BPFObject) == 0 {
		return preflightCheck{Name: "BPF/XDP", Status: preflightFail, Detail: "内置 BPF 对象为空，请重新生成并打包 xdpacl_bpfel.o"}
	}
	if err := deps.probeBPF(opts.BPFObject); err != nil {
		return preflightCheck{Name: "BPF/XDP", Status: preflightFail, Detail: err.Error()}
	}
	return preflightCheck{Name: "BPF/XDP", Status: preflightPass, Detail: "BPF 程序和 XDP 类型程序可加载，实际挂载将按 native、generic 顺序尝试"}
}

func probeBPFObject(object []byte) error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return fmt.Errorf("BPF 对象解析失败: %w", err)
	}
	program, ok := spec.Programs["xdp_acl"]
	if !ok || program == nil || program.Type != ebpf.XDP {
		return errors.New("BPF 对象缺少 xdp_acl XDP 程序")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("解除 BPF memlock 限制失败: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("BPF/XDP 加载失败（请检查内核、CAP_BPF/CAP_NET_ADMIN 和 LSM 限制）: %w", err)
	}
	collection.Close()
	return nil
}

func checkIPTables(opts preflightOptions, deps preflightDeps) preflightCheck {
	if opts.InstallMode == "server-only" {
		return preflightCheck{Name: "iptables", Status: preflightSkip, Detail: "server-only 模式不运行本机数据面"}
	}
	if opts.Dataplane != "iptables" {
		return preflightCheck{Name: "iptables", Status: preflightSkip, Detail: "当前数据面为 XDP/eBPF，不需要 iptables 兼容后端"}
	}
	if deps.goos != "linux" {
		return preflightCheck{Name: "iptables", Status: preflightFail, Detail: "iptables 数据面只能在 Linux 上运行"}
	}
	if _, err := deps.lookPath("iptables"); err != nil {
		return preflightCheck{Name: "iptables", Status: preflightFail, Detail: fmt.Sprintf("找不到 iptables: %v", err)}
	}
	for _, table := range []string{"raw", "mangle"} {
		if output, err := deps.runCommand("iptables", "-t", table, "-S"); err != nil {
			return preflightCheck{Name: "iptables", Status: preflightFail, Detail: fmt.Sprintf("无法读取 %s 表: %v%s", table, err, formatCommandOutput(output))}
		}
	}
	return preflightCheck{Name: "iptables", Status: preflightPass, Detail: "iptables 可执行，raw/mangle 表可访问"}
}

func checkSSHLogSource(opts preflightOptions, deps preflightDeps) preflightCheck {
	if opts.InstallMode == "server-only" {
		return preflightCheck{Name: "SSH 日志", Status: preflightSkip, Detail: "server-only 模式不运行本机 Agent"}
	}
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if info, err := deps.stat(path); err == nil && info.Mode().IsRegular() {
			return preflightCheck{Name: "SSH 日志", Status: preflightPass, Detail: "使用 " + path}
		}
	}
	if _, err := deps.lookPath("journalctl"); err == nil {
		if _, probeErr := deps.runCommand("journalctl", "--no-pager", "--quiet", "--output=cat", "--since", "1 minute ago"); probeErr == nil {
			return preflightCheck{Name: "SSH 日志", Status: preflightPass, Detail: "未发现 auth.log/secure，将使用 journald"}
		}
		return preflightCheck{Name: "SSH 日志", Status: preflightWarn, Detail: "找到 journalctl，但 journald 当前不可读取；启用 SSH 登录防护前请检查 systemd journal"}
	}
	return preflightCheck{Name: "SSH 日志", Status: preflightWarn, Detail: "未发现 /var/log/auth.log、/var/log/secure 或 journalctl；SSH 登录防护启用前需配置日志来源"}
}

func formatCommandOutput(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}
	return ": " + output
}

func installPreflightOptions(mode, dataplane, requestedDataplane string, enableServices, allowPortReuse bool, iface, agentAddr, serverAddr, serverGRPCAddr, serverQUICAddr string, bpfObject []byte) preflightOptions {
	return preflightOptions{
		Dataplane:          dataplane,
		RequestedDataplane: requestedDataplane,
		InstallMode:        mode,
		EnableServices:     enableServices,
		AllowPortReuse:     allowPortReuse,
		DefaultInterface:   iface,
		AgentAddr:          agentAddr,
		ServerAddr:         serverAddr,
		ServerGRPCAddr:     serverGRPCAddr,
		ServerQUICAddr:     serverQUICAddr,
		BPFObject:          bpfObject,
	}
}
