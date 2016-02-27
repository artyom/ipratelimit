// Package ipratelimit provides http.Handler capable of per-IP rate limiting
package ipratelimit

import (
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPFunc type function should extract IP address from http request. If returned
// IP is nil or it is not a valid IPv4 (IP.To4() returns nil), request is
// allowed without additional processing.
type IPFunc func(*http.Request) net.IP

// New return http.Handler that wraps provided handler and applies per-IP rate
// limiting. Only IPv4 addresses are supported. If ipfunc is nil,
// IPFromRemoteAddr is used. If burst is less than 1, value 1 is used. If logger
// is nil, logging is disabled. For each IP address it uses a separate initially
// filled "token bucket" of burst size; every interval bucket is refilled with
// a token. If request hits limit, "429 Too Many Requests" response is served.
func New(interval time.Duration, burst int, h http.Handler, ipfunc IPFunc, logger *log.Logger) http.Handler {
	if h == nil {
		panic("nil handler")
	}
	if interval <= 0 {
		panic("non-positive interval")
	}
	if ipfunc == nil {
		ipfunc = IPFromRemoteAddr
	}
	if burst < 1 {
		burst = 1
	}
	return &limiter{
		refillEvery: float64(interval),
		burst:       float64(burst),
		handler:     h,
		ipfunc:      ipfunc,
		ipmap:       make(map[uint32]*bucket, MaxCapacity),
		log:         logger,
	}
}

type limiter struct {
	refillEvery float64
	burst       float64
	handler     http.Handler
	ipfunc      IPFunc
	m           sync.Mutex
	ipmap       map[uint32]*bucket
	log         *log.Logger
}

type bucket struct {
	left  float64   // tokens left
	mtime time.Time // last access time
}

func (h *limiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := h.ipfunc(r)
	if ip == nil || ip.To4() == nil {
		h.handler.ServeHTTP(w, r)
		return
	}
	key := ip2key(ip)
	now := time.Now()
	var allow bool
	h.m.Lock()
	bkt, ok := h.ipmap[key]
	if !ok {
		bkt = &bucket{left: h.burst}
		h.ipmap[key] = bkt
	}
	if l := len(h.ipmap); l >= MaxCapacity {
		i, r := 0, rand.Intn(10)
		for k := range h.ipmap {
			// remove random 10% of map
			if i%10 == r {
				delete(h.ipmap, k)
			}
			i++
		}
	}

	if !bkt.mtime.IsZero() {
		// refill bucket
		spent := now.Sub(bkt.mtime)
		if refillBy := float64(spent) / h.refillEvery; refillBy > 0 {
			bkt.left += refillBy
			if bkt.left > h.burst {
				bkt.left = h.burst
			}
		}
	}
	if bkt.left >= 1 {
		bkt.left -= 1
		allow = true
	}
	bkt.mtime = now

	h.m.Unlock()
	if !allow {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		if h.log != nil {
			h.log.Printf("rate limited for %v: %s %s", ip, r.Method, r.URL)
		}
		return
	}
	h.handler.ServeHTTP(w, r)
}

// IPFromXForwardedFor extracts first IP address from X-Forwarded-For header of
// the request
func IPFromXForwardedFor(r *http.Request) net.IP {
	ffor := r.Header.Get("X-Forwarded-For")
	if ffor == "" {
		return nil
	}
	if idx := strings.Index(ffor, ","); idx > 0 {
		ffor = ffor[:idx]
	}
	return net.ParseIP(ffor)
}

// IPFromRemoteAddr returns IP address of connected client, use this only if
// clients connect directly to your service.
func IPFromRemoteAddr(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func ip2key(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		panic("non ipv4 ip")
	}
	var u uint32
	u |= uint32(ip[0]) << 24
	u |= uint32(ip[1]) << 16
	u |= uint32(ip[2]) << 8
	u |= uint32(ip[3])
	return u
}

// maximum number of IPs to track, on overflow evict random items
const MaxCapacity = 100000
