// Package dnsresolve provides bounded, cached reverse-DNS lookups for
// telemetry. DNS is only an enrichment source; callers must continue to use
// the IP address for policy decisions because one address can host many names.
package dnsresolve

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout      = 250 * time.Millisecond
	defaultPositiveTTL  = 5 * time.Minute
	defaultNegativeTTL  = 30 * time.Second
	defaultConcurrency  = 8
	defaultCacheEntries  = 4096
	maxLookupAddresses   = 64
)

// LookupFunc is injectable so resolver behavior can be tested without using
// the host's DNS configuration.
type LookupFunc func(context.Context, string) ([]string, error)

type cacheEntry struct {
	name      string
	expiresAt time.Time
}

// Resolver performs reverse-DNS lookups with short timeouts and separate
// positive/negative cache lifetimes. A failed lookup is intentionally cached
// briefly because telemetry is refreshed frequently.
type Resolver struct {
	mu          sync.Mutex
	cache       map[string]cacheEntry
	lookup      LookupFunc
	timeout     time.Duration
	positiveTTL time.Duration
	negativeTTL time.Duration
	concurrency int
	maxEntries  int
}

// New creates a resolver backed by the system resolver.
func New() *Resolver {
	return NewWithLookup(func(ctx context.Context, ip string) ([]string, error) {
		return net.DefaultResolver.LookupAddr(ctx, ip)
	})
}

// NewWithLookup creates a resolver with an injectable reverse-DNS function.
// It is useful for deterministic tests and for deployments that provide a
// local DNS integration.
func NewWithLookup(lookup LookupFunc) *Resolver {
	if lookup == nil {
		lookup = func(ctx context.Context, ip string) ([]string, error) {
			return net.DefaultResolver.LookupAddr(ctx, ip)
		}
	}
	return &Resolver{
		cache:       make(map[string]cacheEntry),
		lookup:      lookup,
		timeout:     defaultTimeout,
		positiveTTL: defaultPositiveTTL,
		negativeTTL: defaultNegativeTTL,
		concurrency: defaultConcurrency,
		maxEntries:  defaultCacheEntries,
	}
}

func normalizeIP(value string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.IsUnspecified() || addr.IsMulticast() {
		return "", false
	}
	return addr.String(), true
}

func normalizeName(value string) string {
	name := strings.TrimSpace(strings.TrimSuffix(value, "."))
	if name == "" || strings.ContainsAny(name, " \t\r\n/") {
		return ""
	}
	return strings.ToLower(name)
}

// Lookup returns one normalized PTR name for an IP. The bool is false when no
// usable name is available; the original IP should then be shown by callers.
func (r *Resolver) Lookup(ctx context.Context, value string) (string, bool) {
	if r == nil {
		return "", false
	}
	ip, ok := normalizeIP(value)
	if !ok {
		return "", false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	r.mu.Lock()
	if cached, exists := r.cache[ip]; exists && cached.expiresAt.After(now) {
		r.mu.Unlock()
		return cached.name, cached.name != ""
	}
	lookup := r.lookup
	timeout := r.timeout
	positiveTTL := r.positiveTTL
	negativeTTL := r.negativeTTL
	r.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	names, err := lookup(lookupCtx, ip)
	cancel()
	name := ""
	if err == nil {
		for _, candidate := range names {
			if normalized := normalizeName(candidate); normalized != "" {
				name = normalized
				break
			}
		}
	}
	ttl := negativeTTL
	if name != "" {
		ttl = positiveTTL
	}
	r.mu.Lock()
	if r.maxEntries > 0 && len(r.cache) >= r.maxEntries {
		for cachedIP, cached := range r.cache {
			if !cached.expiresAt.After(time.Now()) {
				delete(r.cache, cachedIP)
			}
		}
		if len(r.cache) >= r.maxEntries {
			for cachedIP := range r.cache {
				delete(r.cache, cachedIP)
				break
			}
		}
	}
	r.cache[ip] = cacheEntry{name: name, expiresAt: time.Now().Add(ttl)}
	r.mu.Unlock()
	return name, name != ""
}

// LookupMany resolves distinct IPs concurrently with a small upper bound so
// a telemetry refresh cannot create an unbounded number of DNS requests.
func (r *Resolver) LookupMany(ctx context.Context, values []string) map[string]string {
	result := make(map[string]string)
	if r == nil || len(values) == 0 {
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unique := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, ok := normalizeIP(value)
		if !ok {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
		if len(unique) >= maxLookupAddresses {
			break
		}
	}
	if len(unique) == 0 {
		return result
	}
	concurrency := r.concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	if concurrency > len(unique) {
		concurrency = len(unique)
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var resultMu sync.Mutex
	for _, ip := range unique {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if name, ok := r.Lookup(ctx, ip); ok {
				resultMu.Lock()
				result[ip] = name
				resultMu.Unlock()
			}
		}()
	}
	wg.Wait()
	return result
}
