//go:build !linux

package api

import "errors"

func validKernelModuleName(string) bool { return false }
func kernelModuleLoaded(string) bool    { return false }

func loadKernelModule(string, string) (string, error) {
	return "", errors.New("当前平台不支持加载内核模块")
}

func unloadKernelModule(string, string) (string, error) {
	return "", errors.New("当前平台不支持卸载内核模块")
}
