package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// refreshMargin is how long before exp the ID token is replaced, so a
	// request never reaches Squid with a token about to expire in flight.
	refreshMargin = 60 * time.Second
	// maxCredential keeps `<login> <token>` under Squid's 8,192-byte helper
	// line. Squid does not answer a login that once exceeded it, so the relay
	// refuses instead of sending it.
	maxCredential = 8000
	httpTimeout   = 10 * time.Second
)

var errLoginRequired = errors.New("login required")

// session holds the user's tokens in memory only: a restart means a new login.
type session struct {
	oauth         *oauth2.Config
	client        *http.Client
	usernameClaim string
	callbackAddr  string
	callbackPath  string

	mu       sync.Mutex
	login    string
	idToken  string
	expiry   time.Time
	refresh  string
	state    string
	verifier string
	authURL  string
	now      func() time.Time
}

func newSession(cfg config, ep endpoints, client *http.Client) *session {
	u, _ := url.Parse(cfg.redirectURL)
	return &session{
		oauth: &oauth2.Config{
			ClientID:    cfg.clientID,
			Endpoint:    oauth2.Endpoint{AuthURL: ep.AuthURL, TokenURL: ep.TokenURL},
			RedirectURL: cfg.redirectURL,
			Scopes:      []string{"openid", "profile", "email", "groups", "offline_access"},
		},
		client:        client,
		usernameClaim: cfg.usernameClaim,
		callbackAddr:  u.Host,
		callbackPath:  u.Path,
		now:           time.Now,
	}
}

func (s *session) proxyAuthorization() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.idToken != "" && s.expiry.Sub(s.now()) > refreshMargin {
		return s.basic()
	}
	if s.refresh != "" {
		err := s.refreshLocked()
		if err == nil {
			return s.basic()
		}
		slog.Warn("refresh failed", "error", err)
	}
	s.clearLocked()
	s.startLoginLocked()
	return "", fmt.Errorf("%w: open %s", errLoginRequired, s.authURL)
}

func (s *session) rejected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
	s.startLoginLocked()
}

func (s *session) basic() (string, error) {
	if len(s.login)+1+len(s.idToken) > maxCredential {
		return "", fmt.Errorf("ID token is %d bytes, over the %d the proxy accepts: ask for fewer groups in the token", len(s.idToken), maxCredential)
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(s.login+":"+s.idToken)), nil
}

// providerContext hands the relay's client to oauth2, which takes its HTTP
// client from the context. The client's own timeout bounds each call.
func (s *session) providerContext() context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, s.client)
}

func (s *session) refreshLocked() error {
	tok, err := s.oauth.TokenSource(s.providerContext(), &oauth2.Token{RefreshToken: s.refresh}).Token()
	if err != nil {
		return err
	}
	return s.storeLocked(tok)
}

func (s *session) storeLocked(tok *oauth2.Token) error {
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return errors.New("token response has no id_token")
	}
	login, exp, err := readClaims(raw, s.usernameClaim)
	if err != nil {
		return err
	}
	s.login, s.idToken, s.expiry, s.refresh = login, raw, exp, tok.RefreshToken
	slog.Info("token stored", "login", login, "expires", exp.Format(time.RFC3339))
	return nil
}

func (s *session) clearLocked() {
	s.login, s.idToken, s.expiry, s.refresh = "", "", time.Time{}, ""
}

// No signature check here, not a second verifier: the token comes straight
// from the token endpoint over TLS, and the proxy's helper verifies it on
// every use.
func readClaims(raw, usernameClaim string) (string, time.Time, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", time.Time{}, errors.New("id_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("id_token payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", time.Time{}, fmt.Errorf("id_token payload: %w", err)
	}
	login, _ := claims[usernameClaim].(string)
	if login == "" {
		return "", time.Time{}, fmt.Errorf("id_token has no %s claim", usernameClaim)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("id_token has no exp claim")
	}
	return login, time.Unix(int64(exp), 0), nil
}
