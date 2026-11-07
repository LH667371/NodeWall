//go:build !linux

package filemeta

import "os"

// Production SSH hooks target Linux. Other platforms retain ordinary mode and
// ownership handling and can exercise the protocol in isolated tests.
func CopyAccessAttrs(_, _ *os.File) error { return nil }
