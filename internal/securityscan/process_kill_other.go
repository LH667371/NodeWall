//go:build !linux

package securityscan

import "fmt"

type ProcessTermination struct {
	PID    int    `json:"pid"`
	Method string `json:"method"`
	Signal string `json:"signal"`
	Forced bool   `json:"forced"`
	Exited bool   `json:"exited"`
}

func kernelProcessExists(int) bool { return false }

func terminateProcess(pid int) (ProcessTermination, error) {
	return ProcessTermination{PID: pid}, fmt.Errorf("kernel process control is only supported on Linux")
}

func TerminateProcess(pid int) (ProcessTermination, error) {
	return terminateProcess(pid)
}
