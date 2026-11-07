package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"nodewall/internal/models"
)

type sshAccessInfo struct {
	Ports   []uint16 `json:"ports"`
	Clients []string `json:"clients"`
}

func activeSSHClientIPs(procRoot string, ports []uint16) []string {
	listeners := make(map[uint16]bool)
	for _, port := range ports {
		listeners[port] = true
	}
	seen := make(map[string]bool)
	var result []string
	for _, name := range []string{"tcp", "tcp6"} {
		data, _ := os.ReadFile(filepath.Join(procRoot, "net", name))
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "01" {
				continue
			}
			_, localPort, _ := strings.Cut(fields[1], ":")
			port, err := strconv.ParseUint(localPort, 16, 16)
			if err != nil || !listeners[uint16(port)] {
				continue
			}
			remote, _, _ := strings.Cut(fields[2], ":")
			address, err := hex.DecodeString(remote)
			if err != nil || (len(address) != 4 && len(address) != 16) {
				continue
			}
			// procfs renders IPv4 and each IPv6 word in native little-endian order.
			for i := 0; i < len(address); i += 4 {
				address[i], address[i+3] = address[i+3], address[i]
				address[i+1], address[i+2] = address[i+2], address[i+1]
			}
			ip, ok := netip.AddrFromSlice(address)
			if !ok {
				continue
			}
			value := ip.Unmap().String()
			if !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	return result
}

func tcpAccessAllowed(policy models.DirectionPolicy, source netip.Addr, port uint16) bool {
	if policy.ObserveOnly {
		return true
	}
	contains := func(cidrs []string) bool {
		for _, raw := range cidrs {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil && prefix.Contains(source) {
				return true
			}
		}
		return false
	}
	portMatch := func(rules []models.PortRule, legacy []uint16) bool {
		for _, rule := range models.NormalizePortRules(rules, legacy) {
			if rule.Protocol == models.PortProtocolTCP && rule.Port == port {
				return true
			}
		}
		return false
	}
	if contains(policy.BypassCIDRs) {
		return true
	}
	if contains(policy.BlockedCIDRs) || portMatch(policy.DeniedPortRules, policy.DeniedPorts) {
		return false
	}
	if portMatch(policy.PublicPortRules, policy.PublicPorts) {
		return true
	}
	if len(policy.AllowedPorts) > 0 || len(policy.AllowedPortRules) > 0 {
		return portMatch(policy.AllowedPortRules, policy.AllowedPorts)
	}
	cidrs := extractCIDRs(policy.Rules)
	if contains(cidrs) {
		return true
	}
	// An empty ingress map is fail-open; once any policy map is populated,
	// unmatched IPv4 traffic is denied by the native dataplane.
	return len(cidrs)+len(policy.BypassCIDRs)+len(policy.BlockedCIDRs)+len(policy.ICMPAllowCIDRs)+len(policy.ICMPBlockedCIDRs)+len(policy.PublicPortRules)+len(policy.PublicPorts)+len(policy.DeniedPortRules)+len(policy.DeniedPorts) == 0
}

func (h *ServerHandler) blockUnsafeSSHPolicy(w http.ResponseWriter, r *http.Request, current, next models.InterfacePolicy, password string) bool {
	before, after := models.DirectionPolicyFor(current, models.DirectionIngress), models.DirectionPolicyFor(next, models.DirectionIngress)
	if reflect.DeepEqual(before, after) {
		return false
	}
	var info sshAccessInfo
	if err := h.nodeJSON(r.Context(), next.NodeID, http.MethodGet, "/system/ssh", nil, &info); err != nil || len(info.Ports) == 0 {
		writeError(w, http.StatusBadGateway, errors.New("cannot detect the node's active sshd ports; policy was not changed"))
		return true
	}
	if ip, ok := requestSourceAddr(r); ok {
		info.Clients = append(info.Clients, ip.String())
	}
	risky := false
	for _, port := range info.Ports {
		// Adding an allow rule must remain a routine firewall operation. The
		// confirmation protects the active SSH session only when the resulting
		// policy can remove access to that port.
		beforeAction := effectiveTCPPortAction(before, port)
		afterAction := effectiveTCPPortAction(after, port)
		if beforeAction == "allow" && afterAction != "allow" {
			risky = true
		}
		for _, raw := range info.Clients {
			ip, err := netip.ParseAddr(raw)
			if err == nil && tcpAccessAllowed(before, ip, port) && !tcpAccessAllowed(after, ip, port) {
				risky = true
			}
		}
	}
	if len(info.Clients) == 0 {
		for _, port := range info.Ports {
			if effectiveTCPPortAction(before, port) == "allow" && effectiveTCPPortAction(after, port) != "allow" {
				risky = true
				break
			}
		}
	}
	if risky && (h.auth == nil || !h.auth.verifyCurrentPassword(r, password)) {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "SSH_CONFIRM_REQUIRED", "error": "ssh confirmation required", "service": "sshd", "ports": info.Ports})
		return true
	}
	return false
}

func (h *ServerHandler) blockUnsafeSSHDisposition(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost || requestDirection(r) != models.DirectionIngress {
		return false
	}
	var body struct {
		Source   string `json:"source_ip"`
		Port     uint16 `json:"port"`
		Protocol string `json:"protocol"`
	}
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid protection request"))
		return true
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if json.Unmarshal(data, &body) != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid protection request"))
		return true
	}
	if strings.EqualFold(body.Protocol, "udp") {
		return false
	}
	var info sshAccessInfo
	if err := h.nodeJSON(r.Context(), r.PathValue("node"), http.MethodGet, "/system/ssh", nil, &info); err != nil || len(info.Ports) == 0 {
		writeError(w, http.StatusBadGateway, errors.New("cannot detect sshd ports; protection rule was not changed"))
		return true
	}
	if ip, ok := requestSourceAddr(r); ok {
		info.Clients = append(info.Clients, ip.String())
	}
	risky := false
	for _, port := range info.Ports {
		if body.Port == port {
			risky = true
		}
		if body.Port == 0 || body.Port == port {
			for _, ip := range info.Clients {
				if ip == body.Source {
					risky = true
				}
			}
		}
	}
	if risky && (h.auth == nil || !h.auth.verifyCurrentPassword(r, confirmationPassword(r))) {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "SSH_CONFIRM_REQUIRED", "error": "ssh confirmation required", "ports": info.Ports})
		return true
	}
	return false
}

// Retain a bounded copy of JSON mutation requests so every handler can read
// confirmation metadata even after decoding its own request type.
func captureConfirmation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileUpload := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ssh-sessions/") && strings.HasSuffix(r.URL.Path, "/files")
		mutation := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch
		if r.Body != nil && mutation && !fileUpload {
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
			data, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				writeError(w, http.StatusRequestEntityTooLarge, errors.New("JSON request exceeds 2 MB"))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
		}
		next.ServeHTTP(w, r)
	})
}

func confirmationPassword(r *http.Request) string {
	if value := r.Header.Get("X-Nodewall-Confirm-Password"); value != "" {
		return value
	}
	if r.GetBody != nil {
		body, err := r.GetBody()
		if err == nil {
			defer body.Close()
			var req struct {
				Password string `json:"confirm_password"`
			}
			if json.NewDecoder(io.LimitReader(body, 2<<20)).Decode(&req) == nil {
				return req.Password
			}
		}
	}
	return r.URL.Query().Get("confirm_password")
}
