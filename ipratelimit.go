// Package ipratelimit provides http.Handler capable of per-IP rate limiting
package ipratelimit

import (
	"log"
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
		ipmap:       make(map[uint32]bucket, MaxCapacity),
		keys:        make(chan uint32, MaxCapacity),
		log:         logger,
	}
}

type limiter struct {
	refillEvery float64
	burst       float64
	handler     http.Handler
	ipfunc      IPFunc
	m           sync.Mutex
	ipmap       map[uint32]bucket
	keys        chan uint32 // fifo queue of unique keys, chan must be buffered to the size of ipmap
	log         *log.Logger
}

type bucket struct {
	left  float64 // tokens left
	mtime int64   // last access time as nanoseconds since Unix epoch
}

func (h *limiter) allow(ip net.IP) (allow, evictDone bool, evictDuration time.Duration) {
	key := ip2key(ip)
	now := time.Now()
	h.m.Lock()
	defer h.m.Unlock()
	bkt, ok := h.ipmap[key]
	if !ok {
		bkt = bucket{left: h.burst}
	}
	if l := len(h.ipmap); l >= MaxCapacity {
		for i := 0; i < MaxCapacity/10; i++ {
			select {
			case k := <-h.keys:
				delete(h.ipmap, k)
			default:
				panic("receive from h.keys is blocked")
			}
		}
		evictDone = true
		evictDuration = time.Since(now)
	}
	if !ok {
		// push new key to fifo queue here and not above because it's
		// essential to do eviction before pushing to ensure queue has
		// free space
		select {
		case h.keys <- key:
		default:
			panic("push to h.keys is blocked")
		}
	}

	if bkt.mtime != 0 {
		// refill bucket
		spent := now.Sub(time.Unix(0, bkt.mtime))
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
	bkt.mtime = now.UnixNano()
	h.ipmap[key] = bkt

	return allow, evictDone, evictDuration
}

func (h *limiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := h.ipfunc(r)
	if ip == nil || ip.To4() == nil {
		h.handler.ServeHTTP(w, r)
		return
	}
	allow, evictDone, evictDuration := h.allow(ip)
	if evictDone && h.log != nil {
		h.log.Print("excess limit buckets evicted in ", evictDuration)
	}
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
