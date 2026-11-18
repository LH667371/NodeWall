//go:build !linux

package securityscan

func collectSystemIntegrityFindings() []Finding { return nil }
