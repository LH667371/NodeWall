//go:build !linux

package securityscan

func scanMountPoints(string) (map[string]string, error) {
	return map[string]string{}, nil
}
