# Changelog

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
