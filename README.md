# proxy-relay-oidc

A local HTTP proxy for one user. It logs in to an OIDC provider in the browser,
then relays the user's browser and CLI traffic to an upstream proxy over TLS,
adding `Proxy-Authorization: Basic <login>:<ID token>`. Tools keep pointing at a
proxy on `127.0.0.1`; the login and the token refresh happen here.

The upstream proxy checks the token. For Squid that is
[squid-auth-oidc](https://github.com/zinrai/squid-auth-oidc), and
[squid-auth-oidc-lab](https://github.com/zinrai/squid-auth-oidc-lab) runs the
two together with Dex.

## Install

Download the binary for your OS and architecture from the
[releases](https://github.com/zinrai/proxy-relay-oidc/releases).
`proxy-relay-oidc -version` prints which release it is.

## Run

```
proxy-relay-oidc \
  -listen 127.0.0.1:3128 \
  -proxy squid.example.com:3129 \
  -issuer https://dex.example.com/dex \
  -client-id squid-relay \
  -redirect-url http://127.0.0.1:8085/callback \
  -username-claim preferred_username
```

| Flag | Meaning |
|------|---------|
| `-listen` | Where tools connect. A loopback IP address only |
| `-proxy` | Upstream proxy `host:port`, spoken to over TLS |
| `-issuer` | Issuer URL of the OIDC provider |
| `-client-id` | Client ID registered at the provider for this relay |
| `-redirect-url` | Redirect URL registered for that client. http on a loopback IP address |
| `-username-claim` | ID token claim sent as the login. It must match the proxy's helper |

All are required.

The certificates of the proxy and the provider are checked against the
system trust store. Give the proxy's TLS port a certificate from a public CA,
such as Let's Encrypt; the provider's is already trusted there, since users
log in to it with the browser.

At start the relay logs the URL of the provider's login page; open it in a
browser to log in. Until the login completes, requests get `502` naming the
URL too. Then point tools at the relay:

```
export http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128
```

and set the same address as the browser's proxy.

## Provider client

Register a public client (no secret) with the redirect URL above, allowed to
use the authorization code and refresh token grants. The relay asks for the
scopes `openid profile email groups offline_access` and uses PKCE (S256). The
provider must return an ID token and a refresh token.

## Behaviour

- Tokens are kept in memory only. Restarting the relay means logging in again.
- The ID token is refreshed when it has under a minute left. An expired token
  is never sent.
- When the refresh fails, or the proxy refuses the token (`407`), the relay
  drops the tokens and starts a new login, whose URL is in the log and in the
  `502` body.
- Errors are answered `502` with the reason as text, never `407`: a browser
  answers `407` with its own password dialog.
- A login plus token over 8,000 bytes is not sent. Squid limits its helper
  line to 8,192 bytes and stops answering a login that exceeded it. Fewer
  groups in the token fix this.
- Proxy headers sent by the client are replaced. `CONNECT` requests become
  tunnels; browsers send WebSocket through `CONNECT` too. A plain-HTTP request
  asking for a protocol upgrade is answered `502`.

The listener accepts any local process, as any local proxy does.

## License

This project is licensed under the [MIT License](LICENSE).
