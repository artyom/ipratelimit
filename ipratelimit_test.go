package ipratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func BenchmarkLimiter(b *testing.B) {
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "192.168.0.1")
	handler := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello\n")) }
	lh := New(time.Second/10, 5, http.HandlerFunc(handler), IpFromXForwardedFor)
	var allowed, limited int
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		lh.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			allowed++
		}
		if w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	b.Logf("reqs %d, allowed/limited: %d/%d ", allowed+limited, allowed, limited)
}
