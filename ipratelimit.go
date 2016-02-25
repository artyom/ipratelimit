package ipratelimit

import (
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type IpFunc func(*http.Request) net.IP

func New(interval time.Duration, burst int, h http.Handler, ipfunc IpFunc) http.Handler {
	if h == nil {
		panic("nil handler")
	}
	if ipfunc == nil {
		ipfunc = IpFromRemoteAddr
	}
	if burst < 1 {
		burst = 1
	}
	return &limiter{
		limit:   rate.Every(interval),
		burst:   burst,
		handler: h,
		ipfunc:  ipfunc,
		ipmap:   make(map[uint32]*rate.Limiter, mapCap),
	}
}

type limiter struct {
	limit   rate.Limit
	burst   int
	handler http.Handler
	ipfunc  IpFunc
	m       sync.Mutex
	ipmap   map[uint32]*rate.Limiter
}

func (h *limiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := h.ipfunc(r)
	if ip == nil || ip.To4() == nil {
		h.handler.ServeHTTP(w, r)
		return
	}
	key := ip2key(ip)
	h.m.Lock()
	lim, ok := h.ipmap[key]
	if !ok {
		lim = rate.NewLimiter(h.limit, h.burst)
		h.ipmap[key] = lim
	}
	if l := len(h.ipmap); l >= mapCap {
		i, r := 0, rand.Intn(10)
		for k := range h.ipmap {
			// remove random 10% of map
			if i%10 == r {
				delete(h.ipmap, k)
			}
			i++
		}
	}
	h.m.Unlock()
	if !lim.Allow() {
		//log.Printf("rate limited for %v (exceeds limit of %v/second)", net.IP(key[:]), lim.Limit()) // XXX
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func IpFromXForwardedFor(r *http.Request) net.IP {
	ffor := r.Header.Get("X-Forwarded-For")
	if ffor == "" {
		return nil
	}
	if idx := strings.Index(ffor, ","); idx > 0 {
		ffor = ffor[:idx]
	}
	return net.ParseIP(ffor)
}

func IpFromRemoteAddr(r *http.Request) net.IP {
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

const mapCap = 100000
