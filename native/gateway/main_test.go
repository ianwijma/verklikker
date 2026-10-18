package main

import (
	"encoding/json"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func policyFixture(t *testing.T, action string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(decision{Action: action, Reason: "fixture"})
	})}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })
	client = &http.Client{Timeout: time.Second, Transport: &http.Transport{Dial: func(_, _ string) (net.Conn, error) { return net.Dial("unix", path) }}}
	cfg = config{Bytes: 1024 * 1024, BytesPerSecond: 1024 * 1024, Connections: 2}
	slots = make(chan struct{}, 2)
	limiter = rate.NewLimiter(rate.Inf, 65536)
	total = atomic.Int64{}
}
func TestDenyAndUnknownPolicyNeverDial(t *testing.T) {
	for _, action := range []string{"deny", "", "unexpected"} {
		t.Run(action, func(t *testing.T) {
			policyFixture(t, action)
			if c, e := dial("tcp", "127.0.0.1:1"); e == nil {
				c.Close()
				t.Fatal("expected policy refusal")
			}
			if len(slots) != 0 {
				t.Fatal("failed authorization leaked connection slot")
			}
		})
	}
}
func TestWritesKeepTheEntirePayload(t *testing.T) {
	policyFixture(t, "allow")
	a, b := net.Pipe()
	defer b.Close()
	slots <- struct{}{}
	c := &counted{Conn: &wireConn{Conn: a}}
	defer c.Close()
	done := make(chan int)
	go func() { n, _ := io.Copy(io.Discard, b); done <- int(n) }()
	payload := make([]byte, 150000)
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("write=%d err=%v", n, err)
	}
	c.Close()
	if received := <-done; received != len(payload) {
		t.Fatalf("received %d", received)
	}
}
func TestBudgetStopsDataAndReleasesSlots(t *testing.T) {
	policyFixture(t, "allow")
	cfg.Bytes = 3
	a, b := net.Pipe()
	defer b.Close()
	slots <- struct{}{}
	c := &counted{Conn: &wireConn{Conn: a}}
	if _, err := c.Write([]byte("over-budget")); err == nil {
		t.Fatal("expected byte limit")
	}
	c.Close()
	c.Close()
	if len(slots) != 0 {
		t.Fatal("connection slot leaked")
	}
}
