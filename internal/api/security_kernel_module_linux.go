//go:build linux

package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func validKernelModuleName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func kernelModuleLoaded(name string) bool {
	if !validKernelModuleName(name) {
		return false
	}
	_, err := os.Stat(filepath.Join("/sys/module", name))
	return err == nil
}

// loadKernelModule deliberately uses insmod with the quarantined payload path.
// This keeps the original file in quarantine and avoids copying an untrusted
// module back into a boot/search path merely to make a reversible operator test.
func loadKernelModule(name, payloadPath string) (string, error) {
	name = strings.TrimSpace(name)
	payloadPath = filepath.Clean(strings.TrimSpace(payloadPath))
	if !validKernelModuleName(name) {
		return "", errors.New("无法确认内核模块名称")
	}
	if payloadPath == "." || payloadPath == "" {
		return "", errors.New("隔离区没有可加载的模块文件")
	}
	if !isQuarantineChild(payloadPath) {
		return "", errors.New("拒绝从隔离区之外加载内核模块")
	}
	if kernelModuleLoaded(name) {
		return "already_loaded", nil
	}
	info, err := os.Lstat(payloadPath)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("隔离模块不是普通文件")
	}
	var failures []string
	for _, command := range [][]string{{"/sbin/insmod", payloadPath}, {"/usr/sbin/insmod", payloadPath}} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		output, commandErr := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput()
		cancel()
		if commandErr != nil {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = commandErr.Error()
			}
			failures = append(failures, command[0]+": "+message)
			continue
		}
		if err := waitForKernelModulePresence(name); err != nil {
			failures = append(failures, command[0]+": "+err.Error())
			continue
		}
		return command[0], nil
	}
	return "", fmt.Errorf("内核模块加载失败: %s", strings.Join(failures, "; "))
}

func unloadKernelModule(name, sysfsPath string) (string, error) {
	name = strings.TrimSpace(name)
	if !validKernelModuleName(name) {
		return "", errors.New("无法确认内核模块名称")
	}
	var failures []string
	for _, command := range [][]string{{"/sbin/modprobe", "-r", name}, {"/usr/sbin/modprobe", "-r", name}, {"/sbin/rmmod", name}, {"/usr/sbin/rmmod", name}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput()
		cancel()
		if err != nil {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = err.Error()
			}
			failures = append(failures, command[0]+": "+message)
			continue
		}
		if err := waitForKernelModuleRemoval(sysfsPath); err != nil {
			failures = append(failures, command[0]+": "+err.Error())
			continue
		}
		return command[0], nil
	}
	if len(failures) == 0 {
		return "", errors.New("未执行内核模块卸载命令")
	}
	return "", fmt.Errorf("内核模块仍在运行: %s", strings.Join(failures, "; "))
}

func waitForKernelModuleRemoval(path string) error {
	for attempt := 0; attempt < 20; attempt++ {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("sysfs 对象仍存在: %s", path)
}

func waitForKernelModulePresence(name string) error {
	path := filepath.Join("/sys/module", name)
	for attempt := 0; attempt < 20; attempt++ {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("sysfs 对象未出现: %s", path)
}
