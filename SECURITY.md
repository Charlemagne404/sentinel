# Security and privacy

## Network and transport

The server selects an address from the configured tailscale* interface (default tailscale0) and falls back to loopback only. It does not bind wildcard addresses or alter firewall/Headscale policy. Application login is still required. Sentinel currently serves HTTP, so remote sessions rely on the encrypted Tailnet/WireGuard path. Do not expose the port through a public reverse proxy or port forward. TLS certificates are not supported.

## Authentication controls

- First-run bootstrap token: 256 random bits, owner-only file, 30-minute validity, single use.
- Administrator password: minimum 12 bytes, letter and non-alphanumeric character; Argon2id password hash.
- Session: random token stored only as SHA-256 digest, 12-hour default expiry, server-side revocation on logout/reset.
- Cookie: HttpOnly, SameSite=Strict, Path=/ and expiry. Secure is not set because the listener is HTTP; remote access must stay on the encrypted private network.
- Mutating protected API calls require same-origin validation and a CSRF token. Protected requests validate Host.
- Login is limited to five failed attempts per peer in a rolling 15-minute window.
- Responses set CSP, frame, referrer and content-type protections; request bodies are limited to 64 KiB.

## Data handling

Sentinel does not read process environment variables or unrestricted command lines. Process history records a bounded selection of identity, executable, ownership, cgroup/workload and resource fields. There is no outbound telemetry. Notification requests go only to configured validated providers. Local AI requests go only to loopback and contain sanitized incident evidence, selected metrics, related process fields and failed-service summaries; no commands, environment, unrestricted logs, or credentials are included. AI is disabled by default and refused when host pressure exceeds guardrails.

Configuration, bootstrap token, database, and user unit use restrictive permissions where created by Sentinel/scripts. Protect the account and backups. The browser stores only theme preference in localStorage; authentication uses an HttpOnly cookie.

## Operational limits

Sentinel is read-only and does not run remediation commands. It does not require root. Permission or kernel-layout limitations are surfaced as missing data. The user-level systemd service adds resource and filesystem restrictions; verify actual compatibility and status on the host before relying on it.
