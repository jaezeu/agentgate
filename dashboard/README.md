# AgentGate operations dashboard

This directory contains the human operations SPA for active grants, pending
approvals, and immutable decision history. It is a React/TypeScript/Vite
application and has no backend of its own.

Read `../docs/ARCHITECTURE.md` before changing authentication, API, or
credential boundaries.

## Security boundary

- Humans authenticate through OIDC Authorization Code with PKCE. A SPIFFE SVID,
  Workload API socket, or task grant is never accepted as dashboard identity.
- OIDC access and refresh tokens are kept in memory by `oidc-client-ts`. Only
  transient protocol state and the PKCE verifier use `sessionStorage`. Tokens
  are never put in `localStorage`, the DOM, application logs, or Vite
  configuration.
- The current AgentGate `OIDCAuthenticator` verifies the OIDC ID token as the
  human bearer, so the client supplies that memory-only token to the human API.
- The browser calls only the AgentGate human API. It does not call Vault, AWS,
  Kubernetes, Terraform, SPIRE, a dispatcher, or a credential redemption path.
- The only browser writes are:
  `POST /v1/requests/{id}/approve`,
  `POST /v1/requests/{id}/deny`, and
  `POST /v1/requests/{id}/revoke`.
- Human API responses are runtime-validated. Unknown enum values produce a
  visible compatibility error. Credential-shaped fields, task signatures,
  nonces, and workload redemption descriptors are rejected before rendering.
- Server authorization is authoritative. The countdown is display-only and is
  adjusted from the response `server_time` or HTTP `Date` header.
- Revoke prevents new access and requests best-effort Vault cleanup. AWS STS
  credentials already issued may remain usable until expiry; TTL is the primary
  control.

## API integration

The SPA is isolated behind `src/api/client.ts` and consumes the AgentGate human
routes implemented in `../internal/api`:

- `GET /v1/requests` with bounded `limit`/`offset` and server-side filters;
- `GET /v1/requests/{id}` for the immutable timeline;
- the exact three POST actions listed above.

The mocked network tests use the same credential-free transport shape as the Go
handlers. `src/api/schema.ts` converts Go's nested request snapshot and
nanosecond `time.Duration` into the display model, rejects unknown enum values,
and never accepts a workload redemption descriptor. The list API supports
bounded pagination plus environment, operation, repository, binding, identity,
time, decision, approval, and active-state filters. Human request detail adds
an explicitly mapped audit timeline without exposing the persisted task grant,
nonce, signature, or generic audit details.

## Configuration

Copy `.env.example` to `.env.local` for local development. Every `VITE_*` value
is public and must be non-secret.

| Variable | Purpose |
| --- | --- |
| `VITE_AGENTGATE_API_BASE_URL` | AgentGate human API origin or same-origin base path |
| `VITE_AUTH_MODE` | `oidc` in deployed builds; `mock` only under the gate below |
| `VITE_OIDC_AUTHORITY` | OIDC issuer/authority URL |
| `VITE_OIDC_CLIENT_ID` | Public SPA client ID; never a client secret |
| `VITE_OIDC_REDIRECT_URI` | Registered callback, normally `/auth/callback` |
| `VITE_OIDC_POST_LOGOUT_REDIRECT_URI` | Registered post-logout destination |
| `VITE_OIDC_SCOPE` | Defaults to `openid profile email` |

Register the client as a public client, require Authorization Code with PKCE,
and do not issue a browser client secret. A page reload intentionally loses the
memory-only session and requires sign-in again.

### Development mock boundary

Mock auth requires all of the following:

```text
VITE_AUTH_MODE=mock
VITE_ENABLE_MOCK_AUTH=true
```

It is additionally gated by Vite's development mode and is rejected by a
production build. The page displays a persistent mock-auth banner. Mock mode
does not embed a static approver bearer token; use a local same-origin
development session or a reverse proxy if the API requires one.

## Local development

Requirements: a supported Node.js release and npm.

```sh
cd dashboard
npm ci
npm run dev
```

Run the merge-bar checks:

```sh
npm run typecheck
npm run lint
npm test
npm run build
```

Tests use MSW at the HTTP boundary. Fixtures intentionally contain no tokens,
leases, cloud keys, private keys, signatures, nonces, or generic secrets.

## Deployment

### AgentGate-served

Build with the public OIDC settings, then run
`agentgate serve --dashboard-dir=/path/to/dashboard/dist`. AgentGate routes
`/v1/*`, `/livez`, and `/readyz` to the API before its SPA fallback and returns
`index.html` for client routes. Static serving does not change route
authentication: the dashboard uses human OIDC, while only the workload API can
consume a verified client X509-SVID.

### Standalone

Host `dashboard/dist` on a static origin and set
`VITE_AGENTGATE_API_BASE_URL` to the human API origin. AgentGate CORS must allow
only the dashboard origin, the `Authorization` and `Content-Type` headers, GET
and POST, and credentials when a secure session cookie is used. Never use `*`
with credentialed CORS.

Cache hashed assets immutably, but serve `index.html` with revalidation so OIDC
and API configuration updates are not pinned. Production source maps are
disabled in `vite.config.ts`.

## Content Security Policy

Set CSP as an HTTP response header and replace the example origins with the
deployed OIDC and AgentGate origins:

```text
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self' https://identity.example.test https://api.example.test;
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  object-src 'none'
```

Also set `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, and a restrictive
`Permissions-Policy`. Add an OIDC frame origin only if the selected session
monitor requires it; do not broadly allow frames or scripts.
