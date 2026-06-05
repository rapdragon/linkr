# Changelog

## [1.4.0] - 2026-06-05

### Added
- Docker Swarm support: after any NPM write (create/edit/delete), Linkr force-reloads all NPM service replicas via the Docker socket to prevent stale nginx config on non-updated replicas
- Config page: optional "Docker Swarm Service Name" field (e.g. `npm_npm`) — leave blank to disable swarm reload
- Requires `/var/run/docker.sock` mounted into the Linkr container when using swarm mode

## [1.3.0] - 2026-06-01

### Added
- Edit page: add/change/remove SSL certificates on existing entries
- Certificate options: Internal CA, Let's Encrypt, or Remove
- Server-side port validation (must be 1–65535) on web form and API
- Server-side domain validation (required, non-empty)
- Force SSL checkbox always visible on edit (not just when cert exists)

### Fixed
- `request_le_cert()`: NPM API no longer accepts `letsencrypt_email`, `letsencrypt_agree`, `dns_challenge` in meta — now sends `"meta": {}`
- Non-numeric port input no longer causes 500 error
- Out-of-range port (e.g. 99999) no longer silently accepted

## [1.2.0] - 2026-05-30

### Added
- Standalone API Keys management (separate from users)
- API Keys page under Config dropdown with name, permission, expiration
- Read-only vs full access permission levels for API keys
- Optional expiration date on API keys
- Config dropdown menu (General, Users, API Keys)

### Changed
- API authentication now uses standalone keys instead of user-tied keys
- Nav restructured: Config is now a dropdown
- Login form has autocomplete attributes for password managers (Bitwarden etc)

### Removed
- "Gen API Key" button from Users page (replaced by API Keys page)

## [1.1.0] - 2026-05-30

### Added
- Edit page for existing FQDNs (change forward host/port, DNS IP, SSL forced)
- Custom cert detection — distinguishes Let's Encrypt from custom/internal CA certs
- "Internal (Custom Cert)" type option when adding domains
- Split DNS support — external domains can optionally add Pi-hole entry for local resolution
- REST API with API key authentication (generate in Users tab)
- API key generation button on Users page

### Changed
- External domains no longer require Pi-hole entry (optional via checkbox)
- DNS-only entries (no proxy) no longer flagged as errors
- Removed fix buttons — edit page handles all modifications
- Browser tab titles now show "Linkr"
- Custom background image and favicon

### Fixed
- Public DNS validation popup JS cleanup

## [1.0.0] - 2026-05-30

### Added
- Initial release
- Web UI with login, setup wizard, home page, config, user management
- Pi-hole DNS host management via v6 API
- NPM proxy host management via API
- One-click FQDN creation (DNS + proxy together)
- One-click FQDN deletion (removes from both systems)
- Mismatch detection (DNS-only or proxy-only entries flagged)
- External domain support with Let's Encrypt cert requests
- Public DNS validation popup before cert requests
- SSL forced redirect toggle per domain
- Let's Encrypt rate limit tracking (50/week warning)
- Duplicate domain prevention
- Auto re-auth on token expiry (Pi-hole + NPM)
- User auth with admin/viewer roles (bcrypt hashed passwords)
- REST API with API key authentication
- Docker containerized deployment
