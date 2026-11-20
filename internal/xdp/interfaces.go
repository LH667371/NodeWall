package xdp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"nodewall/internal/models"
)

// ErrInterfaceNotPresent is returned before any attach attempt when a
// successful link inventory does not contain the requested interface.
var ErrInterfaceNotPresent = errors.New("network interface is not present")

func lookupInterface(name string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrInterfaceNotPresent, name)
}

func DetectHostInterfaces() (models.InterfaceInventory, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return models.InterfaceInventory{}, err
	}

	detected := make([]models.DetectedInterface, 0, len(ifaces))
	masters := make(map[string]string)
	for _, iface := range ifaces {
		item := models.DetectedInterface{
			Name:         iface.Name,
			MTU:          iface.MTU,
			Flags:        normalizeFlags(iface.Flags),
			HardwareAddr: iface.HardwareAddr.String(),
			IsUp:         iface.Flags&net.FlagUp != 0,
			IsLoopback:   iface.Flags&net.FlagLoopback != 0,
			IsPhysical:   looksPhysical(iface),
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			item.Addresses = append(item.Addresses, addr.String())
		}

		detected = append(detected, item)
		if master, err := os.Readlink(filepath.Join("/sys/class/net", iface.Name, "master")); err == nil {
			masters[iface.Name] = filepath.Base(master)
		}
	}
	associateInterfaceAddresses(detected, masters)

	recommended := recommendInterface(detected)
	for i := range detected {
		detected[i].IsRecommended = detected[i].Name == recommended
	}

	sort.Slice(detected, func(i, j int) bool {
		return interfaceScore(detected[i]) > interfaceScore(detected[j])
	})

	return models.InterfaceInventory{
		Interfaces:  detected,
		Recommended: recommended,
	}, nil
}

// A bridge slave often has only link-local IPv6 while its bridge owns the
// management IPv4. Keep that association explicit without changing the NIC's
// own address list or the interface on which a policy is applied.
func associateInterfaceAddresses(items []models.DetectedInterface, masters map[string]string) {
	byName := make(map[string]models.DetectedInterface, len(items))
	for _, item := range items {
		byName[item.Name] = item
	}
	hasIPv4 := func(addresses []string) bool {
		for _, text := range addresses {
			addr, err := netip.ParseAddr(strings.SplitN(text, "/", 2)[0])
			if err == nil && addr.Unmap().Is4() {
				return true
			}
		}
		return false
	}
	for i := range items {
		items[i].AddressInterface, items[i].RelatedAddresses = "", nil
		if hasIPv4(items[i].Addresses) {
			continue
		}
		seen := map[string]bool{items[i].Name: true}
		for master := masters[items[i].Name]; master != "" && !seen[master]; master = masters[master] {
			seen[master] = true
			parent, found := byName[master]
			if !found {
				break
			}
			if hasIPv4(parent.Addresses) {
				items[i].AddressInterface = parent.Name
				items[i].RelatedAddresses = append([]string(nil), parent.Addresses...)
				break
			}
		}
	}
}

func normalizeFlags(flags net.Flags) []string {
	out := make([]string, 0, 4)
	if flags&net.FlagUp != 0 {
		out = append(out, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		out = append(out, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		out = append(out, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		out = append(out, "point-to-point")
	}
	if flags&net.FlagMulticast != 0 {
		out = append(out, "multicast")
	}
	return out
}

func looksPhysical(iface net.Interface) bool {
	name := strings.ToLower(iface.Name)
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}

	virtualPrefixes := []string{
		"lo", "docker", "veth", "br-", "cni", "flannel", "utun", "gif",
		"stf", "anpi", "tailscale", "wg", "tun", "tap", "virbr", "vboxnet",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	if runtime.GOOS == "linux" {
		// Enterprise hosts frequently use em1/em2 rather than eth* naming.
		// sysfs is authoritative and, unlike a name heuristic, keeps bridges,
		// bonds and virtual devices out of the XDP attach candidate set.
		return physicalFromSysfs("/sys/class/net", iface.Name)
	}

	if runtime.GOOS == "darwin" && strings.HasPrefix(name, "en") {
		return true
	}

	return strings.HasPrefix(name, "eth") ||
		strings.HasPrefix(name, "ens") ||
		strings.HasPrefix(name, "eno") ||
		strings.HasPrefix(name, "enp") ||
		strings.HasPrefix(name, "bond") ||
		strings.HasPrefix(name, "wlan") ||
		strings.HasPrefix(name, "wl")
}

func physicalFromSysfs(root, name string) bool {
	base := filepath.Join(root, name)
	if _, err := os.Stat(filepath.Join(base, "bridge")); err == nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(base, "bonding")); err == nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
		return false
	}
	return true
}

func recommendInterface(items []models.DetectedInterface) string {
	bestName := ""
	bestScore := -1
	for _, item := range items {
		score := interfaceScore(item)
		if score > bestScore {
			bestName = item.Name
			bestScore = score
		}
	}
	return bestName
}

func interfaceScore(item models.DetectedInterface) int {
	score := 0
	if item.IsUp {
		score += 50
	}
	if !item.IsLoopback {
		score += 40
	}
	if item.IsPhysical {
		score += 80
	}
	if len(item.Addresses) > 0 {
		score += 20
	}
	name := strings.ToLower(item.Name)
	preferred := []string{"eth", "ens", "eno", "enp", "bond", "en", "wlan", "wl"}
	for i, prefix := range preferred {
		if strings.HasPrefix(name, prefix) {
			score += 25 - i
			break
		}
	}
	if strings.Contains(name, "docker") || strings.Contains(name, "veth") {
		score -= 60
	}
	return score
}

func mockInventory() models.InterfaceInventory {
	items := []models.DetectedInterface{
		{
			Name:          "eth0",
			MTU:           1500,
			Flags:         []string{"up", "broadcast", "multicast"},
			Addresses:     []string{"192.168.50.10/24"},
			IsUp:          true,
			IsPhysical:    true,
			IsRecommended: true,
		},
		{
			Name:       "lo",
			MTU:        65536,
			Flags:      []string{"up", "loopback"},
			Addresses:  []string{"127.0.0.1/8"},
			IsUp:       true,
			IsLoopback: true,
			IsPhysical: false,
		},
	}
	return models.InterfaceInventory{
		Interfaces:  items,
		Recommended: "eth0",
	}
}

func mergeInventoryWithStates(inventory models.InterfaceInventory, states []string) models.InterfaceInventory {
	seen := make(map[string]struct{}, len(inventory.Interfaces))
	for _, item := range inventory.Interfaces {
		seen[item.Name] = struct{}{}
	}
	for _, iface := range states {
		if _, ok := seen[iface]; ok {
			continue
		}
		inventory.Interfaces = append(inventory.Interfaces, models.DetectedInterface{
			Name:       iface,
			Flags:      []string{},
			IsPhysical: true,
		})
	}
	sort.Slice(inventory.Interfaces, func(i, j int) bool {
		return interfaceScore(inventory.Interfaces[i]) > interfaceScore(inventory.Interfaces[j])
	})
	return inventory
}

func uniqueSortedStrings(items []string) []string {
	items = slices.Clone(items)
	slices.Sort(items)
	return slices.Compact(items)
}
