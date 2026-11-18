package dnsresolve

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestResolverCachesPositiveAndNormalizesName(t *testing.T) {
	var calls atomic.Int32
	resolver := NewWithLookup(func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return []string{"Example.COM."}, nil
	})

	first, ok := resolver.Lookup(context.Background(), "192.0.2.10")
	if !ok || first != "example.com" {
		t.Fatalf("unexpected first lookup: %q %v", first, ok)
	}
	second, ok := resolver.Lookup(context.Background(), "192.0.2.10")
	if !ok || second != first {
		t.Fatalf("unexpected cached lookup: %q %v", second, ok)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one DNS call, got %d", calls.Load())
	}
}

func TestResolverSkipsInvalidAndMulticastAddresses(t *testing.T) {
	var calls atomic.Int32
	resolver := NewWithLookup(func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return []string{"example.com"}, nil
	})
	for _, value := range []string{"not-an-ip", "224.0.0.1", "0.0.0.0"} {
		if name, ok := resolver.Lookup(context.Background(), value); ok || name != "" {
			t.Fatalf("invalid address %q unexpectedly resolved to %q", value, name)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid addresses triggered %d DNS calls", calls.Load())
	}
}

func TestResolverLookupManyDeduplicatesAddresses(t *testing.T) {
	var calls atomic.Int32
	resolver := NewWithLookup(func(_ context.Context, ip string) ([]string, error) {
		calls.Add(1)
		return []string{"host-" + ip + ".example"}, nil
	})
	got := resolver.LookupMany(context.Background(), []string{"192.0.2.10", "192.0.2.10", "192.0.2.11"})
	if len(got) != 2 || got["192.0.2.10"] == "" || got["192.0.2.11"] == "" {
		t.Fatalf("unexpected lookup-many result: %#v", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected two DNS calls, got %d", calls.Load())
	}
}
