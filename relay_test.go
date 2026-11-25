package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const sessionAuth = "Basic c2Vzc2lvbg=="

type fakeCreds struct {
	auth     string
	err      error
	refusals atomic.Int32
}

func (f *fakeCreds) proxyAuthorization() (string, error) { return f.auth, f.err }
func (f *fakeCreds) rejected()                           { f.refusals.Add(1) }

// fakeProxy stands in for Squid over TLS: it accepts only want, records what
// it saw, answers plain requests with 200 and echoes CONNECT tunnels.
type fakeProxy struct {
	srv  *httptest.Server
	want string
	mu   sync.Mutex
	seen []string
}

func newFakeProxy(t *testing.T, want string) *fakeProxy {
	t.Helper()
	p := &fakeProxy{want: want}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProxy) serve(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Proxy-Authorization")
	p.mu.Lock()
	p.seen = append(p.seen, auth)
	p.mu.Unlock()
	if auth != p.want {
		w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect {
		io.WriteString(w, "upstream got "+r.URL.String())
		return
	}
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
	io.Copy(conn, brw)
}

func (p *fakeProxy) lastAuth() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen[len(p.seen)-1]
}

// startRelay runs a relay in front of proxy and returns its address.
func startRelay(t *testing.T, proxy *fakeProxy, creds credentials) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(proxy.srv.Certificate())
	r := &relay{
		upstream:  proxy.srv.Listener.Addr().String(),
		tlsConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"},
		creds:     creds,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go r.serve(ln)
	return ln.Addr().String()
}

// getVia fetches target through the relay as a client that sends its own
// proxy credentials.
func getVia(t *testing.T, relayAddr, target string) *http.Response {
	t.Helper()
	proxyURL := &url.URL{Scheme: "http", Host: relayAddr, User: url.UserPassword("client", "secret")}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestSendsSessionCredentialNotClients(t *testing.T) {
	proxy := newFakeProxy(t, sessionAuth)
	addr := startRelay(t, proxy, &fakeCreds{auth: sessionAuth})

	resp := getVia(t, addr, "http://app.test/api/v1")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "upstream got http://app.test/api/v1" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if got := proxy.lastAuth(); got != sessionAuth {
		t.Fatalf("upstream saw Proxy-Authorization %q, want the session's", got)
	}
}

// connectVia sends CONNECT for target through the relay and returns the
// answer and the connection, with the reader positioned after the answer.
func connectVia(t *testing.T, relayAddr, target string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	// A deadline, so a tunnel that drops one direction fails instead of hanging.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: http.Header{}}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, conn, br
}

func TestTunnelsConnectBothWays(t *testing.T) {
	proxy := newFakeProxy(t, sessionAuth)
	addr := startRelay(t, proxy, &fakeCreds{auth: sessionAuth})

	resp, conn, br := connectVia(t, addr, "app.test:443")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %d", resp.StatusCode)
	}
	io.WriteString(conn, "ping\n")
	if echo, _ := br.ReadString('\n'); echo != "ping\n" {
		t.Fatalf("tunnel echoed %q", echo)
	}
}

// A 407 reaching a browser opens a password dialog nobody can answer. Both
// paths: most sites are HTTPS, so browsers reach them through CONNECT.
func TestRefusedTokenStartsNewLoginWithout407(t *testing.T) {
	via := map[string]func(t *testing.T, addr string) *http.Response{
		"plain HTTP": func(t *testing.T, addr string) *http.Response { return getVia(t, addr, "http://app.test/") },
		"CONNECT": func(t *testing.T, addr string) *http.Response {
			resp, _, _ := connectVia(t, addr, "app.test:443")
			return resp
		},
	}
	for name, send := range via {
		t.Run(name, func(t *testing.T) {
			creds := &fakeCreds{auth: sessionAuth}
			addr := startRelay(t, newFakeProxy(t, "Basic b3RoZXI="), creds)

			resp := send(t, addr)
			if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Proxy-Authenticate") != "" {
				t.Fatalf("got %d with Proxy-Authenticate %q, want 502 without it", resp.StatusCode, resp.Header.Get("Proxy-Authenticate"))
			}
			if creds.refusals.Load() != 1 {
				t.Fatalf("session told of %d refusals, want 1", creds.refusals.Load())
			}
		})
	}
}

func TestReportsLoginRequiredAs502(t *testing.T) {
	proxy := newFakeProxy(t, sessionAuth)
	addr := startRelay(t, proxy, &fakeCreds{err: errors.New("login required: open https://dex.test/auth")})

	resp := getVia(t, addr, "http://app.test/")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "https://dex.test/auth") {
		t.Fatalf("got %d %q, want 502 naming the login URL", resp.StatusCode, body)
	}
}
