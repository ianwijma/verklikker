package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	gdns "github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type config struct {
	Socket, PolicySocket, Capture, Proxy string
	Bytes, BytesPerSecond                int64
	Connections                          int
}
type decision struct {
	Action, Reason, Host string
	Intercept            bool
}

var client *http.Client
var total atomic.Int64
var limiter *rate.Limiter
var cfg config
var slots chan struct{}

func call(path string, data, result any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	res, err := client.Post("http://policy"+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("policy rejected request: %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(result)
}

type counted struct {
	net.Conn
	once sync.Once
}

func (c *counted) Close() error { c.once.Do(func() { <-slots }); return c.Conn.Close() }
func account(n int) error {
	if total.Add(int64(n)) > cfg.Bytes {
		fmt.Println(`{"type":"limit","reason":"Network byte budget exhausted"}`)
		return errors.New("network byte budget exhausted")
	}
	return limiter.WaitN(context.Background(), n)
}

type wireConn struct{ net.Conn }

func (c *wireConn) Read(b []byte) (int, error) {
	if len(b) > 64*1024 {
		b = b[:64*1024]
	}
	n, err := c.Conn.Read(b)
	if e := account(n); e != nil {
		return n, e
	}
	return n, err
}
func (c *wireConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := len(b)
		if n > 64*1024 {
			n = 64 * 1024
		}
		if err := account(n); err != nil {
			return total, err
		}
		written, err := c.Conn.Write(b[:n])
		total += written
		b = b[written:]
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func dial(network, address string) (net.Conn, error) {
	select {
	case slots <- struct{}{}:
	default:
		return nil, errors.New("connection limit")
	}
	ok := false
	defer func() {
		if !ok {
			<-slots
		}
	}()
	ip, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	var d decision
	if err := call("/authorize", map[string]any{"ip": ip, "port": port, "protocol": network}, &d); err != nil {
		return nil, err
	}
	if d.Action != "allow" && d.Action != "mock" {
		return nil, errors.New(d.Reason)
	}
	var conn net.Conn
	if d.Intercept || d.Action == "mock" {
		if network != "tcp" || cfg.Proxy == "" {
			return nil, errors.New("interception unavailable")
		}
		p, e := proxy.SOCKS5("tcp", cfg.Proxy, nil, &net.Dialer{Timeout: 15 * time.Second})
		if e != nil {
			return nil, e
		}
		// The proxy repeats authorization after resolving this name and before connecting.
		conn, err = p.Dial(network, net.JoinHostPort(d.Host, portText))
	} else {
		conn, err = net.DialTimeout(network, address, 15*time.Second)
	}
	if err != nil {
		return nil, err
	}
	ok = true
	return &counted{Conn: conn}, nil
}
func answer(m *dns.Msg) {
	if len(m.Question) != 1 {
		m.Rcode = dns.RcodeRefused
		return
	}
	q := m.Question[0]
	var res struct {
		Addresses []string
		Rcode     int
	}
	if err := call("/dns", map[string]any{"name": q.Name, "type": q.Qtype}, &res); err != nil {
		m.Rcode = dns.RcodeServerFailure
		return
	}
	m.Rcode = res.Rcode
	for _, address := range res.Addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			continue
		}
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
		if q.Qtype == dns.TypeA && ip.To4() != nil {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip.To4()})
		}
		if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
		}
	}
}
func main() {
	configPath := flag.String("config", "", "configuration JSON")
	flag.Parse()
	b, err := os.ReadFile(*configPath)
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(b, &cfg); err != nil {
		panic(err)
	}
	if cfg.Bytes <= 0 || cfg.BytesPerSecond <= 0 || cfg.Connections <= 0 {
		panic("positive network limits required")
	}
	slots = make(chan struct{}, cfg.Connections)
	limiter = rate.NewLimiter(rate.Limit(cfg.BytesPerSecond), 64*1024)
	client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", cfg.PolicySocket)
	}}}
	forwarder.PolicyDial = dial
	gdns.PolicyAnswer = answer
	v, err := virtualnetwork.New(&types.Configuration{MTU: 1500, Subnet: "192.168.127.0/24", GatewayIP: "192.168.127.1", GatewayMacAddress: "5a:94:ef:e4:0c:dd", CaptureFile: cfg.Capture, TCPMaxInFlight: cfg.Connections, TCPConnectTimeout: 15, DHCPStaticLeases: map[string]string{"192.168.127.2": "5a:94:ef:e4:0c:ee"}})
	if err != nil {
		panic(err)
	}
	defer v.Close()
	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	os.Chmod(cfg.Socket, 0600)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()
	fmt.Println(`{"type":"ready"}`)
	// A run has exactly one VM connection. No management HTTP API is exposed.
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	if err = v.AcceptQemu(ctx, &wireConn{Conn: conn}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
