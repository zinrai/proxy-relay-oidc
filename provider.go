package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type endpoints struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
}

func discover(client *http.Client, issuer string) (endpoints, error) {
	var ep endpoints
	resp, err := client.Get(strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return ep, fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ep, fmt.Errorf("discovery: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&ep); err != nil {
		return ep, fmt.Errorf("discovery: %w", err)
	}
	if ep.Issuer != issuer {
		return ep, fmt.Errorf("discovery: issuer is %q, want %q", ep.Issuer, issuer)
	}
	return ep, nil
}
