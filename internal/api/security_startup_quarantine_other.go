//go:build !linux

package api

func prepareSystemdUnitIsolation(string) ([]quarantinedStartupLink, error) { return nil, nil }

func rollbackSystemdUnitIsolation([]quarantinedStartupLink) {}

func restoreSystemdStartupLinks(quarantineMetadata) error { return nil }
