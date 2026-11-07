package api

import (
	"testing"
	"time"

	"nodewall/internal/models"
)

func TestRecentTrafficStatsUsesFiveMinuteDelta(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	trend := []models.TrafficPoint{
		{Timestamp: now.Add(-6 * time.Minute).Format(time.RFC3339), Passed: 100, Dropped: 10},
		{Timestamp: now.Add(-4 * time.Minute).Format(time.RFC3339), Passed: 160, Dropped: 20},
	}

	stats := recentTrafficStats(models.InterfaceStats{Passed: 220, Dropped: 30}, trend, now)
	if stats.RecentPassed != 120 || stats.RecentDropped != 20 {
		t.Fatalf("unexpected five-minute delta: %#v", stats)
	}
	if stats.DropRate != 20.0/140.0 {
		t.Fatalf("unexpected drop rate: %v", stats.DropRate)
	}
	if stats.PassedPPS <= 0 || stats.DroppedPPS <= 0 {
		t.Fatalf("expected positive rates: %#v", stats)
	}
}

func TestRecentTrafficStatsHandlesCounterReset(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	trend := []models.TrafficPoint{{
		Timestamp: now.Add(-time.Minute).Format(time.RFC3339),
		Passed:    900,
		Dropped:   90,
	}}

	stats := recentTrafficStats(models.InterfaceStats{Passed: 12, Dropped: 3}, trend, now)
	if stats.RecentPassed != 12 || stats.RecentDropped != 3 {
		t.Fatalf("counter reset should use current values: %#v", stats)
	}
}
