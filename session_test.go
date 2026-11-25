package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testNow = time.Unix(1_800_000_000, 0)

// idToken builds an unsigned JWT; the relay reads claims without verifying.
func idToken(login string, exp time.Time, padding int) string {
	payload, _ := json.Marshal(map[string]any{
		"preferred_username": login,
		"exp":                exp.Unix(),
		"pad":                strings.Repeat("x", padding),
	})
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(payload) + ".sig"
}

// tokenEndpoint stands in for the provider's token endpoint. It answers a
// refresh grant, or an authorization code grant for "good-code", with next as
// the ID token, and fails every grant when fail is set. login_test.go uses it
// too.
type tokenEndpoint struct {
	srv      *httptest.Server
	calls    atomic.Int32
	verifier atomic.Value
	fail     bool
	next     string
}

func newTokenEndpoint(t *testing.T, next string, fail bool) *tokenEndpoint {
	t.Helper()
	te := &tokenEndpoint{next: next, fail: fail}
	te.srv = httptest.NewServer(http.HandlerFunc(te.serve))
	t.Cleanup(te.srv.Close)
	return te
}

func (te *tokenEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	te.calls.Add(1)
	w.Header().Set("Content-Type", "application/json")
	grant := r.FormValue("grant_type")
	ok := grant == "refresh_token" || (grant == "authorization_code" && r.FormValue("code") == "good-code")
	if te.fail || !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	te.verifier.Store(r.FormValue("code_verifier"))
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "bearer", "expires_in": 120,
		"refresh_token": "r2", "id_token": te.next,
	})
}

// testSession returns a session with no tokens, using te as the token
// endpoint and testNow as the clock. login_test.go uses it too.
func testSession(te *tokenEndpoint) *session {
	cfg := config{clientID: "squid-relay", redirectURL: "http://127.0.0.1:8085/callback", usernameClaim: "preferred_username"}
	s := newSession(cfg, endpoints{AuthURL: "https://dex.test/auth", TokenURL: te.srv.URL}, te.srv.Client())
	s.now = func() time.Time { return testNow }
	return s
}

// sessionHolding returns a session that already holds token, refreshable at te.
func sessionHolding(te *tokenEndpoint, token string) *session {
	s := testSession(te)
	login, exp, err := readClaims(token, "preferred_username")
	if err != nil {
		panic(err)
	}
	s.login, s.idToken, s.expiry, s.refresh = login, token, exp, "r1"
	return s
}

func basicFor(login, token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+token))
}

func TestRefreshesTokenCloseToExpiry(t *testing.T) {
	fresh := idToken("alice", testNow.Add(2*time.Minute), 0)
	te := newTokenEndpoint(t, fresh, false)
	s := sessionHolding(te, idToken("alice", testNow.Add(30*time.Second), 0))

	got, err := s.proxyAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	if got != basicFor("alice", fresh) {
		t.Fatal("did not send the refreshed token")
	}
}

func TestKeepsTokenFarFromExpiry(t *testing.T) {
	current := idToken("alice", testNow.Add(5*time.Minute), 0)
	te := newTokenEndpoint(t, idToken("alice", testNow.Add(10*time.Minute), 0), false)
	s := sessionHolding(te, current)

	got, err := s.proxyAuthorization()
	if err != nil || got != basicFor("alice", current) {
		t.Fatalf("got %q, %v; want the current token", got, err)
	}
	if te.calls.Load() != 0 {
		t.Fatalf("refreshed %d times, want 0", te.calls.Load())
	}
}

func TestNeverSendsExpiredToken(t *testing.T) {
	te := newTokenEndpoint(t, "", true)
	s := sessionHolding(te, idToken("alice", testNow.Add(-time.Second), 0))

	got, err := s.proxyAuthorization()
	if !errors.Is(err, errLoginRequired) || got != "" {
		t.Fatalf("got %q, %v; want no credential and errLoginRequired", got, err)
	}
}

// Squid stops answering a login whose credential once exceeded its line limit.
func TestRefusesOversizedCredential(t *testing.T) {
	te := newTokenEndpoint(t, "", true)
	s := sessionHolding(te, idToken("alice", testNow.Add(5*time.Minute), maxCredential))

	if got, err := s.proxyAuthorization(); err == nil {
		t.Fatalf("sent a %d-byte credential", len(got))
	}
}
