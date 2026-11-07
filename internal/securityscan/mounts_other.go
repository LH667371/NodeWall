//go:build !linux

package securityscan

func scanMountPoints(string) map[string]struct{} {
	return map[string]struct{}{}
}
