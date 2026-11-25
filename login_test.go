package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestStoresTokenFromCallback(t *testing.T) {
	fresh := idToken("alice", testNow.Add(2*time.Minute), 0)
	s := testSession(newTokenEndpoint(t, fresh, false))
	s.startLogin()

	if code := callback(s, "good-code", s.state); code != http.StatusOK {
		t.Fatalf("callback answered %d, want 200", code)
	}
	got, err := s.proxyAuthorization()
	if err != nil || got != basicFor("alice", fresh) {
		t.Fatalf("got %q, %v; want the token from the login", got, err)
	}
}

// Dex refuses the exchange of a public client without the PKCE verifier.
func TestSendsVerifierMatchingChallenge(t *testing.T) {
	te := newTokenEndpoint(t, idToken("alice", testNow.Add(2*time.Minute), 0), false)
	s := testSession(te)
	s.startLogin()
	challenge := queryParam(t, s.authURL, "code_challenge")

	callback(s, "good-code", s.state)
	verifier, _ := te.verifier.Load().(string)
	if s256(verifier) != challenge {
		t.Fatalf("verifier %q does not match challenge %q", verifier, challenge)
	}
}

// s256 derives a PKCE challenge from its verifier (RFC 7636, 4.2).
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// A callback with another state may come from a login someone else started.
func TestRefusesCallbackWithWrongState(t *testing.T) {
	te := newTokenEndpoint(t, idToken("mallory", testNow.Add(2*time.Minute), 0), false)
	s := testSession(te)
	s.startLogin()

	if code := callback(s, "good-code", "forged"); code != http.StatusBadRequest {
		t.Fatalf("callback answered %d, want 400", code)
	}
	if te.calls.Load() != 0 {
		t.Fatal("exchanged the code of a forged callback")
	}
	if _, err := s.proxyAuthorization(); !errors.Is(err, errLoginRequired) {
		t.Fatalf("err = %v, want errLoginRequired", err)
	}
}

// callback delivers the provider's redirect to the relay and returns the status.
func callback(s *session, code, state string) int {
	q := url.Values{"code": {code}, "state": {state}}
	rec := httptest.NewRecorder()
	s.callback(rec, httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil))
	return rec.Code
}

func queryParam(t *testing.T, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(name)
}
