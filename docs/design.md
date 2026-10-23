# Authentication and authorization design

The implementation is an external Go service using Envoy's v3 gRPC authorization API. It authenticates HTTP Basic credentials against a single AD DS domain and requires membership in a service's allowed security groups. The later user requirement to gate access by group makes `group_policy` the deployment default in the examples.

## Check flow

1. Envoy terminates HTTPS and removes the reserved client identity header namespace.
2. The route supplies a server-controlled `policy_id`; unknown or missing policies deny access.
3. The service enforces global/source limits, validates credentials and the configured username namespace, then enforces input-attempt and concurrency limits.
4. In default user mode, a request-scoped LDAPS connection binds with the submitted UPN/password. It discovers the domain naming context and SID, validates the configured domain, and locates a unique account. In optional reader mode, a dedicated reader performs the lookup before submitting user credentials.
5. Global, source, and normalized-input limits apply before LDAP work. Canonical SID admission applies after lookup: before user password submission in reader mode, and after the initial UPN bind but before DN confirmation in user mode. SID admission alone cannot prevent the first user-mode bind through alternate usernames.
6. User mode confirms the password against the resolved canonical DN on the same connection, preventing UPN alias/name collisions from authorizing a different object. Reader mode uses a separate user connection. Rejected or ambiguous binds are never retried or failed over.
7. The authenticated user connection (or optional reader) re-reads that account by DN, verifies its GUID/SID did not change, resolves transitive security memberships, and includes the primary group.
8. Every returned SID is validated against a current security group in the configured search scope, in batches of at most 100. Partial or unsupported results fail closed.
9. Only the selected policy's named groups are looked up on the request's authenticated directory connection. Each must resolve to exactly one current security group in the configured domain, including deny groups. The policy evaluates deny rules first, then all positive conditions, using SIDs internally. An allow result contains verified identity headers and dynamic metadata; all other outcomes stop the upstream request.

## Policy ownership

Policy keys are application/service identifiers, not user-provided resource paths. Envoy selects a policy in route configuration. Policies accept immutable group SIDs or explicit group CN/domain mappings, and support OR membership (`any_of`), AND membership (`all_of`), and deny precedence (`deny_any_of`). Named references are evaluated per request and follow a recreated group's name; use SIDs for stable object identity. A configuration may explicitly allow all authenticated users through `allow_authenticated`, but an empty positive allowlist never grants access accidentally.

The upstream group-export allowlist controls disclosure only. It cannot broaden or narrow a service's authorization decision. The optional enrichment mode is an explicit operator choice for applications that own their authorization.

## Credential and transport boundaries

Client-to-Envoy traffic uses HTTPS. Envoy-to-service connections use mTLS with server SAN validation and an allowed client SAN list, or a private colocated Unix socket with a private parent directory and common UID. Domain-controller connections always use TLS 1.2 or later. Certificate/hostname verification is enabled by default using the OS trust store plus an optional custom CA. Explicit `directory.tls.insecure_skip_verify: true` bypasses that verification and emits a startup/reload warning; this allows server impersonation and password interception. No absent CA, discovery failure, or bind error enables that bypass automatically. The LDAP adapter does not follow referrals, downgrade TLS, perform anonymous binds, or reuse user-bound connections across requests.

User mode requires no stored reader password: the logging-in user must have permission to read discovery, user membership, and selected policy group attributes. LDAP RootDSE supplies `defaultNamingContext`, which is checked against the configured DNS domain; the domain object's SID and optional search-base overrides are validated before authorizing. NetBIOS names are optional and never guessed. Supplying both reader credentials preserves the prior reader workflow; partial credentials or explicit user mode combined with reader credentials are invalid. No fallback silently changes credential identity.

The service accepts one Basic header, splits at the first colon, preserves the password, rejects empty/control-containing/invalid-UTF-8 credentials, and accepts only configured username domains. LDAP filter escaping is applied by the adapter. The service does not receive application bodies. Credentials are stripped before upstream forwarding and never appear in service logs, metrics labels, or public error bodies.

Upstream identity headers are trusted only if direct upstream access is blocked and every upstream request crosses the protected Envoy filter chain. Future filters must not clear the route cache or mutate routing after a check in a way that selects a different authorization policy.

## Membership scope and freshness

`tokenGroups` supplies computed transitive group SIDs. A BASE search, Global Catalog availability, sufficient read rights, and a domain-controller capacity test are prerequisites. The primary group is explicitly derived from the discovered or configured domain SID and returned `primaryGroupID`. Automatic naming-context discovery does not remove the Global Catalog dependency.

The supported result is the single-domain security membership set, not a Windows logon token or general forest authorization model. SID history, cross-forest grants, distribution-list resolution, MFA, Kerberos/NTLM negotiation, sessions, token issuance, and password changes are outside scope. Accounts/groups with SID history or unresolved computed SIDs are rejected rather than granting unsupported rights. AD fixture tests must confirm group-scope and nesting semantics.

No password, successful authentication, or membership cache exists. AD replication and already-open streams limit revocation freshness. Future caching requires a specified revocation window and must not fall back to stale data during directory failure.

## Availability and operations

`failure_mode_allow` is false and Envoy transport errors return 503. The service distinguishes authentication rejection (401), group denial (403), malformed input (400), admission rejection (429), and operational failure (503). LDAP diagnostic details are kept out of responses and logs.

A single request context bounds LDAP work; cancellation closes its connections. Slots and rate-key storage are bounded. Rate-key exhaustion rejects new keys rather than evicting active counters. Per-process budgets must be partitioned across the maximum deployment size; these counters are not a distributed quota.

Configuration snapshots are immutable. SIGHUP validates and probes the replacement before atomic publication; in-flight checks retain their old snapshot. Listener and admission changes require restart. Readiness probes are cached and rate-limited: user mode proves LDAPS connectivity only and submits no credentials; reader mode also checks the reader bind. Discovery and read permissions, named-group resolution, and membership are checked on the request path.

Production acceptance requires live AD semantics, lockout/expiry behavior, AD signing/channel-binding compatibility, and an agreed request/LDAP-operation budget. The default 1.8-second deadline and 600 checks per minute are configurable limits, not measured AD capacity promises.

## References

- [Envoy external authorization filter](https://www.envoyproxy.io/docs/envoy/v1.40.0/configuration/http/http_filters/ext_authz_filter)
- [Envoy authorization service v3](https://www.envoyproxy.io/docs/envoy/v1.40.0/api-v3/service/auth/v3/external_auth.proto)
- [Microsoft tokenGroups attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups)
- [Microsoft LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
- [Microsoft RootDSE](https://learn.microsoft.com/en-us/windows/win32/adsi/rootdse)
- [Microsoft AD simple bind name forms](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6a5891b8-928e-4b75-a4a5-0e3b77eaca52)
