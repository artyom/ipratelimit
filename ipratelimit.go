package ipratelimit

import (
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type IpFunc func(*http.Request) ([net.IPv4len]byte, bool)

func New(interval time.Duration, h http.Handler, ipfunc IpFunc) http.Handler {
	if ipfunc == nil {
		ipfunc = IpFromRemoteAddr
	}
	return &limiter{
		limit:   rate.Every(interval),
		handler: h,
		ipfunc:  ipfunc,
		ipmap:   make(map[[net.IPv4len]byte]*rate.Limiter, mapCap),
		evict:   make([][net.IPv4len]byte, 0, mapCap/10),
	}
}

type limiter struct {
	limit   rate.Limit
	handler http.Handler
	ipfunc  IpFunc
	m       sync.Mutex
	ipmap   map[[net.IPv4len]byte]*rate.Limiter
	evict   [][net.IPv4len]byte // evict candidates
}

func (h *limiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key, ok := h.ipfunc(r)
	if !ok {
		h.handler.ServeHTTP(w, r)
		return
	}
	h.m.Lock()
	lim, ok := h.ipmap[key]
	if !ok {
		lim = rate.NewLimiter(h.limit, 2) // XXX configurable burst?
		h.ipmap[key] = lim
	}
	if rand.Intn(100) < 5 {
		if l, c := len(h.evict), cap(h.evict); l < c {
			h.evict = append(h.evict, key)
		} else {
			h.evict[rand.Intn(l)] = key
		}
	}
	if l, el := len(h.ipmap), len(h.evict); l > mapCap && el > 0 {
		// evict something from map
		cand := h.evict[rand.Intn(el)]
		delete(h.ipmap, cand)
	}
	h.m.Unlock()
	if !lim.Allow() {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func IpFromXForwardedFor(r *http.Request) ([net.IPv4len]byte, bool) {
	ffor, ok := r.Header["X-Forwarded-For"]
	if !ok {
		return emptyKey, false
	}
	if len(ffor) == 0 {
		return emptyKey, false
	}
	ip := net.ParseIP(ffor[0]) // TODO: pick proper record
	if ip == nil {
		return emptyKey, false
	}
	ipv4 := ip.To4()
	out := emptyKey
	copy(out[:], ipv4)
	return out, ipv4 != nil
}

func IpFromRemoteAddr(r *http.Request) ([net.IPv4len]byte, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return emptyKey, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return emptyKey, false
	}
	ipv4 := ip.To4()
	out := emptyKey
	copy(out[:], ipv4)
	return out, ipv4 != nil
}

var emptyKey [net.IPv4len]byte

const mapCap = 100000
