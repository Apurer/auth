# Envoy Active Directory authentication

A Go service implementing Envoy's gRPC v3 `ext_authz` API. It verifies a username and password against AD DS, resolves nested security groups, and authorizes each protected service against an explicit group allowlist.

## Configure allowed groups

In [examples/auth.yaml](examples/auth.yaml), define a policy for each service. `any_of` means membership in **at least one** listed group is required, including nested membership:

```yaml
mode: group_policy
policies:
  orders:
    any_of:
      - S-1-5-21-111111111-222222222-333333333-1101
      - S-1-5-21-111111111-222222222-333333333-1102
  reports:
    any_of:
      - S-1-5-21-111111111-222222222-333333333-1103
```

Use the groups' real SIDs. On a machine with the Active Directory PowerShell module:

```powershell
Get-ADGroup -Identity 'Orders Users' | Select-Object Name, SID
(Get-ADDomain).DomainSID.Value
```

SID matching survives group renames and does not accidentally grant access to a new group with a reused name. `all_of` requires every listed group; `deny_any_of` takes precedence. If both `any_of` and `all_of` are present, both conditions must pass. Empty positive policies are rejected; `allow_authenticated: true` is an explicit alternative for an authenticated-only service.

Envoy selects the service policy using **server-controlled route configuration**:

```yaml
typed_per_filter_config:
  envoy.filters.http.ext_authz:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
    check_settings:
      context_extensions:
        policy_id: orders
```

The complete [Envoy example](examples/envoy.yaml) protects `/orders/` and `/reports/` with separate policies. A missing or unknown policy denies access. Clients cannot select a policy through a request header. Add the route block to a virtual host to protect an entire service rather than a path prefix. Do not add route-mutating filters after authorization or disable the filter on a protected route.

## Build and run

Use Go 1.26 or later with current security patches:

```sh
go mod download
go build -trimpath -o bin/envoy-ad-auth ./cmd/auth
./bin/envoy-ad-auth -config examples/auth.yaml
```

Replace all example domain names, directory bases, SIDs, endpoints, and certificate paths before running. The configuration is strict: unknown fields, insecure LDAP endpoints, missing policies, and invalid limits fail validation.

Provision these read-only files outside the repository:

| File in the examples | Purpose |
| --- | --- |
| `ad-ca.pem` | CA that validates the domain controllers' LDAPS certificates |
| `ad-reader-password` | Exact directory reader password bytes, **without a trailing newline** |
| `auth-cert.pem`, `auth-key.pem` | Authentication service certificate and key; DNS SAN `auth.example.com` |
| `envoy-client-ca.pem` | CA trusted to issue Envoy client certificates |
| `envoy-cert.pem`, `envoy-key.pem` | Envoy client certificate and key; DNS SAN `envoy.example.com` |
| `auth-ca.pem` | CA used by Envoy to verify the authentication service |
| `service-cert.pem`, `service-key.pem` | Public HTTPS certificate and key for the protected application |

The two example processes share a host/network namespace. For separate hosts or containers, change listener and cluster addresses, preserve mTLS verification in both directions, and keep the admin endpoint private. The service requires a verified client certificate with an allowed DNS or URI SAN; a certificate from the trusted CA alone is insufficient. TLS 1.2 is the minimum.

A colocated Unix socket is also supported with `listen: unix:/run/envoy-ad-auth/auth.sock`. The service creates it with mode `0600`; Envoy must run as the same UID and use an HTTP/2 pipe cluster. The parent directory must be private. TCP always requires mTLS.

Run Envoy 1.40.0 with the example config and route it to your upstream applications. Keep upstream ports reachable only from Envoy. The example uses local upstream ports 8080 and 8081; use authenticated TLS for a remote upstream.

```sh
envoy --mode validate -c examples/envoy.yaml
envoy -c examples/envoy.yaml
curl --cacert /path/to/public-service-ca.pem --user 'EXAMPLE\alice' \
  https://service.example.com:8443/orders/
```

`curl` prompts for the password rather than placing it in shell history. Supported usernames are `user@configured-suffix`, `DOMAIN\user`, and bare usernames only when enabled. Each protected request supplies HTTP Basic credentials over HTTPS. There is no login endpoint, session cookie, or token cache.

## Result and failure contract

| Result | HTTP status |
| --- | --- |
| Password accepted and group policy matched | Request forwarded upstream |
| Missing or rejected credentials/account | 401 with a Basic challenge |
| Malformed or duplicate credentials | 400 |
| Credentials exceed configured size | 431, or earlier Envoy header rejection |
| No allowed group, explicit deny, missing or unknown policy | 403 |
| Attempt rate exceeded | 429 |
| Directory failure, partial/unsupported membership result, timeout, overload, or auth service outage | 503 |

Envoy strips client-provided `x-auth-*` headers before authentication. On success the service replaces the identity headers and removes `Authorization` before upstream forwarding:

| Header | Value |
| --- | --- |
| `x-auth-user-sid` | User SID |
| `x-auth-user-upn` | Canonical UPN escaped using Go `url.PathEscape`; decode once if needed |
| `x-auth-group-sids` | JSON array of sorted group SIDs from `export_groups` |

Authorization uses **all resolved groups**, independently of the upstream export allowlist. An empty `export_groups` exports `[]`. Full resolved membership and configuration version are also available to later Envoy filters through `ext_authz` dynamic metadata. Do not expose identity metadata to clients or treat asserted headers as trusted outside the Envoy boundary.

## Directory requirements

Use one AD DS domain with LDAPS enabled and Global Catalog availability. The reader needs access to account `objectSid`, `objectGUID`, `userPrincipalName`, `primaryGroupID`, `sIDHistory`, and `tokenGroups`, and group `objectSid`, `groupType`, and `sIDHistory`. Use a dedicated reader without administrative/write rights and a group base that includes every supported group, normally the domain root.

The service searches for exactly one account, binds as that user on a separate connection, reads `tokenGroups` with BASE scope, explicitly includes the primary group, and verifies returned SIDs against current security group objects. User and reader connections are never shared across requests. Referral chasing is disabled. Rejected or ambiguous user binds are never retried. Connection setup can fail over among the configured controllers before credentials are submitted.

Version 1 deliberately rejects users/groups with SID history, unresolved or out-of-scope SIDs, distribution groups in the computed result, ranged or missing membership attributes, and partial LDAP results. These are operational errors, not a reduced or empty group set. Cross-domain/forest memberships are outside the supported topology. Verify global, universal, domain local, nested, and primary-group behavior in your AD fixtures before production.

`tokenGroups` is expensive for domain controllers. Every request currently performs reader and user binds plus uncached membership resolution. Benchmark at your expected load with the directory owner. Each configured endpoint gets at most 500 ms for connection setup, within the shared request deadline. The default total check budget is 1.8 seconds; the Envoy example allows 2 seconds.

## Operations

- Send `SIGHUP` after replacing configuration, reader-password, or AD-CA files to load a new snapshot. It is published only after validation and a successful reader probe. Failed reloads retain the previous snapshot. In-flight requests use one snapshot throughout.
- Listener addresses, listener TLS identities/files, and admission limits require restart. Updating certificate bytes at the same path also requires restart. Rotate reader secrets using SIGHUP; rotate server/client trust with a rolling restart.
- `SIGINT` and `SIGTERM` drain for up to five seconds, then stop.
- `/livez`, `/readyz`, and `/metrics` are served on the configured **loopback** admin listener. Readiness uses a cached reader-connectivity probe every 15 seconds. It does not prove Global Catalog or membership-read permissions; request-time failures still deny access.
- Prometheus metrics cover decisions, check latency, in-flight requests, LDAP phase latency/errors, and group counts. Logs include only a bounded decision category and duration. Credentials and directory diagnostic strings are never logged. Disable core dumps and credential capture in your hosting platform.
- Rate limits and concurrency are bounded per process. Partition the agreed aggregate AD budget across the **maximum number of replicas**, including rollout surge, before increasing replicas. Also provide a deployment-wide edge rate limit if a shared quota is needed. Fixed one-minute windows may permit a boundary burst; coordinate limits with AD account-lockout policy.
- Neither authentication decisions nor memberships are cached. Account/password changes remain subject to AD replication; existing long-lived streams are not continuously reauthorized. Memory copies are minimized but Go password strings cannot be guaranteed to be zeroized.

Explicit `mode: enrichment` resolves and forwards identity without a gateway group policy. Use `group_policy`, as in the example, when group membership must control access.

## Validation

```sh
go test -race ./...
go vet ./...
ENVOY_BINARY=/absolute/path/to/envoy go test -race ./integration -run TestEnvoy -v
```

The Envoy test runs real HTTPS requests through the example filter chain and an mTLS gRPC service. It covers allowed and disallowed groups, separate service policies, invalid/missing/duplicate credentials, header spoofing, upstream credential removal, directory errors, and auth-service outage. Its directory is a deterministic fixture. Separate adapter tests cover LDAP responses, cancellation, failover, and actual TLS verification.

The live AD test is opt-in. See [AD acceptance](docs/ad-acceptance.md) for prerequisites and the production acceptance matrix. A passing fixture test is not evidence of real AD compatibility or sustainable domain-controller load.

See [design](docs/design.md) for boundaries and implementation decisions.
