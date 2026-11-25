// proxy-relay-oidc is a local HTTP proxy that logs in to an OIDC provider and
// relays requests to an upstream proxy with the ID token as Basic credentials.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type config struct {
	listen        string
	proxy         string
	issuer        string
	clientID      string
	redirectURL   string
	usernameClaim string
	showVersion   bool
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy-relay-oidc:", err)
		os.Exit(2)
	}
	if cfg.showVersion {
		printVersion()
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := run(cfg); err != nil {
		slog.Error("stopped", "error", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("proxy-relay-oidc", flag.ContinueOnError)
	fs.StringVar(&cfg.listen, "listen", "", "loopback address to accept proxy clients on, such as 127.0.0.1:3128")
	fs.StringVar(&cfg.proxy, "proxy", "", "upstream proxy host:port, reached over TLS")
	fs.StringVar(&cfg.issuer, "issuer", "", "issuer URL of the OIDC provider")
	fs.StringVar(&cfg.clientID, "client-id", "", "OIDC client ID registered for this relay")
	fs.StringVar(&cfg.redirectURL, "redirect-url", "", "loopback redirect URL registered for the client, such as http://127.0.0.1:8085/callback")
	fs.StringVar(&cfg.usernameClaim, "username-claim", "", "ID token claim sent as the proxy login")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version information and exit")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if cfg.showVersion {
		return cfg, nil
	}
	if err := requireFlags(fs, "listen", "proxy", "issuer", "client-id", "redirect-url", "username-claim"); err != nil {
		return cfg, err
	}
	// Loopback only: anyone who reaches the listener proxies with this user's identity.
	if err := requireLoopback(cfg.listen); err != nil {
		return cfg, fmt.Errorf("-listen: %w", err)
	}
	u, err := url.Parse(cfg.redirectURL)
	if err != nil {
		return cfg, fmt.Errorf("-redirect-url: %w", err)
	}
	if u.Scheme != "http" {
		return cfg, fmt.Errorf("-redirect-url must be http on a loopback address, got %q", cfg.redirectURL)
	}
	if err := requireLoopback(u.Host); err != nil {
		return cfg, fmt.Errorf("-redirect-url: %w", err)
	}
	// A path, not the bare host: the callback is served on it alone.
	if u.Path == "" || u.Path == "/" {
		return cfg, fmt.Errorf("-redirect-url needs a path, such as /callback, got %q", cfg.redirectURL)
	}
	return cfg, nil
}

func requireFlags(fs *flag.FlagSet, names ...string) error {
	var missing []string
	for _, name := range names {
		if fs.Lookup(name).Value.String() == "" {
			missing = append(missing, "-"+name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return nil
}

func requireLoopback(hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback IP address", host)
	}
	return nil
}

func run(cfg config) error {
	tlsConfig, err := upstreamTLS(cfg.proxy)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: httpTimeout}
	endpoints, err := discover(client, cfg.issuer)
	if err != nil {
		return err
	}
	sess := newSession(cfg, endpoints, client)
	if err := sess.listenCallback(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	sess.startLogin()
	slog.Info("relaying", "listen", cfg.listen, "proxy", cfg.proxy)
	r := &relay{upstream: cfg.proxy, tlsConfig: tlsConfig, creds: sess}
	return r.serve(ln)
}

// The proxy's certificate is checked against the system trust store only, not
// a CA file passed in: the proxy uses a certificate from a public CA, so the
// relay ships as a single binary with nothing else to distribute.
func upstreamTLS(proxy string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(proxy)
	if err != nil {
		return nil, fmt.Errorf("-proxy: %w", err)
	}
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, nil
}
