// Package ipmath provides IP/CIDR parsing, safety validation, deduplication,
// CIDR merging and allowlist subtraction. It is pure (no I/O) and is the
// only place address math happens.
package ipmath

import (
	"fmt"
	"net/netip"
	"strings"

	"go4.org/netipx"
)

// ParsePrefix parses a bare IP ("1.2.3.4", "2001:db8::1") or a CIDR
// ("1.2.3.0/24") into a normalized (masked) prefix.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP %q: %w", s, err)
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Policy controls which prefixes are accepted into a blocklist.
type Policy struct {
	// AllowPrivate accepts RFC1918/ULA and other special-purpose ranges.
	AllowPrivate bool
	// MinV4Bits rejects IPv4 prefixes broader than this (default 8,
	// i.e. /7 and shorter are refused). 0 uses the default.
	MinV4Bits int
	// MinV6Bits is the IPv6 equivalent (default 16).
	MinV6Bits int
}

func (p Policy) minBits(isV4 bool) int {
	if isV4 {
		if p.MinV4Bits > 0 {
			return p.MinV4Bits
		}
		return 8
	}
	if p.MinV6Bits > 0 {
		return p.MinV6Bits
	}
	return 16
}

// specialV4/specialV6 are special-purpose ("bogon") ranges that must never
// be blocked from a feed: blocking them either does nothing useful or
// breaks the host itself (loopback, link-local, multicast, broadcast...).
var specialV4 = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"10.0.0.0/8",      // RFC1918
	"100.64.0.0/10",   // CGNAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local
	"172.16.0.0/12",   // RFC1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.168.0.0/16",  // RFC1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved + broadcast
)

var specialV6 = mustPrefixes(
	"::/128",        // unspecified
	"::1/128",       // loopback
	"::ffff:0:0/96", // IPv4-mapped
	"100::/64",      // discard-only
	"2001:db8::/32", // documentation
	"fc00::/7",      // ULA
	"fe80::/10",     // link-local
	"ff00::/8",      // multicast
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Check returns a non-nil error when the prefix must not enter a blocklist
// under this policy. The error message says why.
func (p Policy) Check(pfx netip.Prefix) error {
	if !pfx.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	isV4 := pfx.Addr().Is4()

	if pfx.Bits() == 0 {
		return fmt.Errorf("default route %s is never allowed", pfx)
	}
	if min := p.minBits(isV4); pfx.Bits() < min {
		return fmt.Errorf("prefix %s broader than /%d", pfx, min)
	}
	if p.AllowPrivate {
		return nil
	}
	special := specialV6
	if isV4 {
		special = specialV4
	}
	for _, s := range special {
		if s.Overlaps(pfx) {
			return fmt.Errorf("prefix %s overlaps special-purpose range %s", pfx, s)
		}
	}
	return nil
}

// Result is the merged, family-split outcome of a build.
type Result struct {
	V4 []netip.Prefix
	V6 []netip.Prefix
}

// Total is the number of prefixes across both families.
func (r Result) Total() int { return len(r.V4) + len(r.V6) }

// Merge deduplicates and merges overlapping/adjacent prefixes, then
// subtracts every allow prefix, returning minimal per-family prefix lists.
// Allowlist subtraction happens after aggregation so an allow entry always
// wins regardless of which feed(s) contributed overlapping blocks.
func Merge(block, allow []netip.Prefix) (Result, error) {
	var b netipx.IPSetBuilder
	for _, pfx := range block {
		b.AddPrefix(pfx)
	}
	for _, pfx := range allow {
		b.RemovePrefix(pfx)
	}
	set, err := b.IPSet()
	if err != nil {
		return Result{}, fmt.Errorf("building IP set: %w", err)
	}

	var res Result
	for _, pfx := range set.Prefixes() {
		if pfx.Addr().Is4() {
			res.V4 = append(res.V4, pfx)
		} else {
			res.V6 = append(res.V6, pfx)
		}
	}
	return res, nil
}

// Contains reports whether any prefix in prefixes covers addr. Used to warn
// when an allowlisted IP shows up in feeds.
func Contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
