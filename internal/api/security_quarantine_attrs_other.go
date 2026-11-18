//go:build !linux

package api

import "os"

func readQuarantineAttrs(_ *os.File) (map[string][]byte, error)  { return nil, nil }
func writeQuarantineAttrs(_ *os.File, _ map[string][]byte) error { return nil }
func verifyTrustedSourceParents(_ string) error                  { return nil }
