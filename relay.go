package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const dialTimeout = 10 * time.Second

// An interface, not *session: tests drive the relay without a provider.
type credentials interface {
	proxyAuthorization() (string, error)
	// rejected reports that the upstream proxy refused the last value.
	rejected()
}

type relay struct {
	upstream  string
	tlsConfig *tls.Config
	creds     credentials
}

func (r *relay) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(conn)
	}
}

// One upstream connection per client connection, not a shared pool: responses
// then come back in the order the client sent its requests.
type upstreamConn struct {
	conn net.Conn
	br   *bufio.Reader
}

func (r *relay) dial() (*upstreamConn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: r.tlsConfig}
	conn, err := d.Dial("tcp", r.upstream)
	if err != nil {
		return nil, err
	}
	return &upstreamConn{conn: conn, br: bufio.NewReader(conn)}, nil
}

func (r *relay) handle(client net.Conn) {
	defer client.Close()
	cbr := bufio.NewReader(client)
	var up *upstreamConn
	defer func() {
		if up != nil {
			up.conn.Close()
		}
	}()

	for {
		req, err := http.ReadRequest(cbr)
		if err != nil {
			return
		}
		auth, err := r.creds.proxyAuthorization()
		if err != nil {
			replyError(client, err.Error())
			return
		}
		if req.Method == http.MethodConnect {
			r.tunnel(client, cbr, req, auth)
			return
		}
		if up == nil {
			up, err = r.dial()
		}
		if err != nil {
			replyError(client, "cannot reach the proxy: "+err.Error())
			return
		}
		if !r.forward(client, up, req, auth) {
			return
		}
	}
}

// forward reports whether the client connection can carry another request.
func (r *relay) forward(client net.Conn, up *upstreamConn, req *http.Request, auth string) bool {
	if err := forwardable(req); err != nil {
		replyError(client, err.Error())
		return false
	}
	resp, err := exchange(up, req, auth)
	if err != nil {
		replyError(client, err.Error())
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		r.refused(client)
		return false
	}
	if err := resp.Write(client); err != nil {
		return false
	}
	return !resp.Close && !req.Close
}

// forwardable refuses protocol upgrades instead of relaying a 101: with a proxy
// set, browsers send WebSocket through CONNECT (RFC 6455, 4.1), which is
// tunnelled.
func forwardable(req *http.Request) error {
	if !req.URL.IsAbs() {
		return fmt.Errorf("not a proxy request: %s", req.URL)
	}
	if req.Header.Get("Upgrade") != "" {
		return errors.New("protocol upgrade over plain HTTP; use CONNECT")
	}
	return nil
}

func exchange(up *upstreamConn, req *http.Request, auth string) (*http.Response, error) {
	setProxyAuth(req.Header, auth)
	if err := req.WriteProxy(up.conn); err != nil {
		return nil, fmt.Errorf("cannot send to the proxy: %w", err)
	}
	resp, err := http.ReadResponse(up.br, req)
	if err != nil {
		return nil, fmt.Errorf("no answer from the proxy: %w", err)
	}
	return resp, nil
}

// The tunnel gets an upstream connection of its own, not the plain-HTTP one:
// once tunnelled, a connection carries raw bytes and no more requests.
func (r *relay) tunnel(client net.Conn, cbr *bufio.Reader, req *http.Request, auth string) {
	up, err := r.dial()
	if err != nil {
		replyError(client, "cannot reach the proxy: "+err.Error())
		return
	}
	defer up.conn.Close()

	fmt.Fprintf(up.conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", req.Host, req.Host, auth)
	resp, err := http.ReadResponse(up.br, req)
	if err != nil {
		replyError(client, "no answer from the proxy: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		r.refused(client)
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Write(client)
		return
	}
	io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	splice(client, cbr, up.conn, up.br)
}

func (r *relay) refused(client net.Conn) {
	r.creds.rejected()
	slog.Warn("proxy refused the token; a new login is needed")
	replyError(client, "the proxy refused the token; log in again (see the relay's log for the URL)")
}

// setProxyAuth replaces whatever proxy headers the client sent, so the
// client cannot speak for anyone else upstream.
func setProxyAuth(h http.Header, auth string) {
	h.Del("Proxy-Authorization")
	h.Del("Proxy-Connection")
	h.Set("Proxy-Authorization", auth)
}

// replyError answers 502 with the reason as text. 502, not 407: a browser
// answers 407 with a password dialog the user can do nothing useful with.
func replyError(client net.Conn, msg string) {
	body := "proxy-relay-oidc: " + msg + "\n"
	fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// Copies from the readers, not the conns: they hold bytes already buffered
// past the HTTP exchange.
func splice(client net.Conn, cr io.Reader, upstream net.Conn, ur io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, cr); done <- struct{}{} }()
	go func() { io.Copy(client, ur); done <- struct{}{} }()
	<-done
	client.Close()
	upstream.Close()
	<-done
}
