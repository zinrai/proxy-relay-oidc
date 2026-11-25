package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/oauth2"
)

func (s *session) startLogin() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startLoginLocked()
}

// startLoginLocked prepares one login attempt; requests that arrive meanwhile
// get the same URL in their error. The URL is only shown, not opened in a
// browser: it reaches the user in the log and in every 502 until the login,
// with no per-OS code.
func (s *session) startLoginLocked() {
	if s.state != "" {
		return
	}
	s.state = rand.Text()
	s.verifier = oauth2.GenerateVerifier()
	s.authURL = s.oauth.AuthCodeURL(s.state, oauth2.S256ChallengeOption(s.verifier))
	slog.Info("log in to continue", "url", s.authURL)
}

func (s *session) listenCallback() error {
	ln, err := net.Listen("tcp", s.callbackAddr)
	if err != nil {
		return fmt.Errorf("callback listener: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(s.callbackPath, s.callback)
	go http.Serve(ln, mux)
	return nil
}

func (s *session) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	verifier, err := s.takePending(q.Get("state"), q.Get("error"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Exchanged outside the lock, not under it: the provider may take seconds,
	// and every proxied request waits on the lock meanwhile.
	tok, err := s.oauth.Exchange(s.providerContext(), q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		slog.Error("login failed", "error", err)
		http.Error(w, "login failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	login, err := s.finishLogin(tok)
	if err != nil {
		slog.Error("login failed", "error", err)
		http.Error(w, "login failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	fmt.Fprintln(w, "Logged in as "+login+". You can close this tab.")
}

// takePending hands out the verifier of the login whose state the provider
// sent back, once: a replayed callback finds no login pending.
func (s *session) takePending(state, providerError string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "" || state != s.state {
		return "", errors.New("unexpected login response; start again from the relay's URL")
	}
	if providerError != "" {
		return "", errors.New("login failed: " + providerError)
	}
	verifier := s.verifier
	s.state, s.verifier, s.authURL = "", "", ""
	return verifier, nil
}

func (s *session) finishLogin(tok *oauth2.Token) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.storeLocked(tok); err != nil {
		return "", err
	}
	// A request during the exchange may have prepared another login; it is moot now.
	s.state, s.verifier, s.authURL = "", "", ""
	return s.login, nil
}
