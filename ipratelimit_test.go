package ipratelimit

import (
	"fmt"
	"log"
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
	cfg := &Config{
		RefillEvery: time.Second / 10,
		Burst:       5,
		IPFunc:      IPFromXForwardedFor,
	}
	lh := New(http.HandlerFunc(handler), cfg)
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

func Example() {
	handler := func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "Hello, world!") }
	cfg := &Config{
		RefillEvery: time.Second / 2,
		Burst:       2,
	}
	lh := New(http.HandlerFunc(handler), cfg)
	ts := httptest.NewServer(lh)
	defer ts.Close()
	for i := 0; i < 3; i++ {
		res, err := http.Get(ts.URL)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(res.Status)
	}
	// Output:
	// 200 OK
	// 200 OK
	// 429 Too Many Requests
}
