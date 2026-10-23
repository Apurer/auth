# Authentication and authorization design

The implementation is an external Go service using Envoy's v3 gRPC authorization API. It authenticates HTTP Basic credentials against a single AD DS domain and requires membership in a service's allowed security groups. The later user requirement to gate access by group makes `group_policy` the deployment default in the examples.

## Check flow

1. Envoy terminates HTTPS and removes the reserved client identity header namespace.
2. The route supplies a server-controlled `policy_id`; unknown or missing policies deny access.
3. The service enforces global/source limits, validates credentials and the configured username namespace, then enforces input-attempt and concurrency limits.
4. An LDAPS reader connection searches an escaped user filter with a two-result limit. Zero matches is an authentication failure; multiple matches are an operational failure.
5. The canonical user SID is rate-limited before the user bind, covering supported aliases that resolve to the same account.
6. A separate connection validates the password with an AD bind. No rejected or ambiguous bind is retried.
7. The reader re-reads the same account by DN, verifies its GUID/SID did not change, resolves transitive security memberships, and includes the primary group.
8. Every returned SID is validated against a current security group in the configured search scope, in batches of at most 100. Partial or unsupported results fail closed.
9. The selected policy evaluates deny rules first, then all configured positive conditions. An allow result contains verified identity headers and dynamic metadata; all other outcomes stop the upstream request.

## Policy ownership

Policy keys are application/service identifiers, not user-provided resource paths. Envoy selects a policy in route configuration. Policies use immutable group SIDs and support OR membership (`any_of`), AND membership (`all_of`), and deny precedence (`deny_any_of`). A configuration may explicitly allow all authenticated users through `allow_authenticated`, but an empty positive allowlist never grants access accidentally.

The upstream group-export allowlist controls disclosure only. It cannot broaden or narrow a service's authorization decision. The optional enrichment mode is an explicit operator choice for applications that own their authorization.

## Credential and transport boundaries

Client-to-Envoy traffic uses HTTPS. The example's Envoy-to-service connection uses mTLS with both server SAN validation and an allowed client SAN list. A private colocated Unix socket is an alternative. Domain-controller connections use a configured CA, hostname verification, and TLS 1.2 or later. The LDAP adapter does not follow referrals, downgrade TLS, perform anonymous binds, or reuse user-bound connections.

The service accepts one Basic header, splits at the first colon, preserves the password, rejects empty/control-containing/invalid-UTF-8 credentials, and accepts only configured username domains. LDAP filter escaping is applied by the adapter. The service does not receive application bodies. Credentials are stripped before upstream forwarding and never appear in service logs, metrics labels, or public error bodies.

Upstream identity headers are trusted only if direct upstream access is blocked and every upstream request crosses the protected Envoy filter chain. Future filters must not clear the route cache or mutate routing after a check in a way that selects a different authorization policy.

## Membership scope and freshness

`tokenGroups` supplies computed transitive group SIDs. A BASE search, Global Catalog availability, sufficient read rights, and a domain-controller capacity test are prerequisites. The primary group is explicitly derived from the configured domain SID and returned `primaryGroupID`.

The supported result is the single-domain security membership set, not a Windows logon token or general forest authorization model. SID history, cross-forest grants, distribution-list resolution, MFA, Kerberos/NTLM negotiation, sessions, token issuance, and password changes are outside scope. Accounts/groups with SID history or unresolved computed SIDs are rejected rather than granting unsupported rights. AD fixture tests must confirm group-scope and nesting semantics.

No password, successful authentication, or membership cache exists. AD replication and already-open streams limit revocation freshness. Future caching requires a specified revocation window and must not fall back to stale data during directory failure.

## Availability and operations

`failure_mode_allow` is false and Envoy transport errors return 503. The service distinguishes authentication rejection (401), group denial (403), malformed input (400), admission rejection (429), and operational failure (503). LDAP diagnostic details are kept out of responses and logs.

A single request context bounds LDAP work; cancellation closes its connections. Slots and rate-key storage are bounded. Rate-key exhaustion rejects new keys rather than evicting active counters. Per-process budgets must be partitioned across the maximum deployment size; these counters are not a distributed quota.

Configuration snapshots are immutable. SIGHUP validates and probes the replacement before atomic publication; in-flight checks retain their old snapshot. Listener and admission changes require restart. Readiness probes are cached and rate-limited; actual membership resolution is always checked on the request path.

Production acceptance requires live AD semantics, lockout/expiry behavior, AD signing/channel-binding compatibility, and an agreed request/LDAP-operation budget. The default 1.8-second deadline and 600 checks per minute are configurable limits, not measured AD capacity promises.

## References

- [Envoy external authorization filter](https://www.envoyproxy.io/docs/envoy/v1.40.0/configuration/http/http_filters/ext_authz_filter)
- [Envoy authorization service v3](https://www.envoyproxy.io/docs/envoy/v1.40.0/api-v3/service/auth/v3/external_auth.proto)
- [Microsoft tokenGroups attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups)
- [Microsoft LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
