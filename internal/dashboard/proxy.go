package dashboard

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// proxies decides what to believe about a request that came through a
// reverse proxy. Forwarded headers are only read from trusted proxies:
// anyone else could send them to fake their address.
type proxies struct {
	trusted []netip.Prefix
}

func parseTrustedProxies(s string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for field := range strings.SplitSeq(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if p, err := netip.ParsePrefix(field); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(field)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %q is neither an address nor a network such as 10.0.1.0/24", field)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func (p *proxies) trusts(addr netip.Addr) bool {
	if p == nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range p.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (p *proxies) fromTrusted(r *http.Request) bool {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && p.trusts(peer.Addr())
}

// clientIP is the address of whoever made the request. Behind trusted
// proxies, it is the right-most address in X-Forwarded-For that is not
// itself a trusted proxy: entries further left were written by the client
// and prove nothing. If every hop is trusted, it is the furthest one.
func (p *proxies) clientIP(r *http.Request) string {
	client := remoteIP(r)
	if !p.fromTrusted(r) {
		return client
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = addr.Unmap().String()
		if !p.trusts(addr) {
			break
		}
	}
	return client
}

// https reports whether the browser's connection is encrypted: TLS here, or
// a trusted proxy saying it terminated HTTPS.
func (p *proxies) https(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return p.fromTrusted(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
