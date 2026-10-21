package hosts

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// MovedAway returns where the hostnames whose entries differ between old and
// next point now, which is where browsers may hold keep-alive connections for
// them. It must run before next is written. A name old has an entry for
// points where that entry says (no lookup: resolvers cache the hosts file for
// a few seconds); any other name is looked up in DNS. Loopback is left out:
// those connections are the proxy's, and it drops them itself
// (proxy.DropKeepAlives).
func MovedAway(old, next *Doc) []netip.Addr {
	before, after := Active(old), Active(next)
	var mu sync.Mutex
	seen := map[netip.Addr]bool{}
	var drop []netip.Addr
	add := func(a netip.Addr) {
		mu.Lock()
		defer mu.Unlock()
		if a = a.Unmap(); !a.IsLoopback() && !seen[a] {
			seen[a] = true
			drop = append(drop, a)
		}
	}
	for h, ip := range before {
		if after[h] != ip {
			if a, err := netip.ParseAddr(ip); err == nil {
				add(a)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for h := range after {
		if _, ok := before[h]; ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, _ := net.DefaultResolver.LookupNetIP(ctx, "ip4", h)
			for _, a := range addrs {
				add(a)
			}
		}()
	}
	wg.Wait()
	return drop
}
