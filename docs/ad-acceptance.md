# Active Directory acceptance

Run against a disposable AD DS domain before production. Unit tests use LDAP response fixtures; the real Envoy test also uses a fixture directory. Neither replaces these checks.

## Fixture

Provision two LDAPS controllers and Global Catalog availability. For default user mode, verify each test user's read access to discovery attributes, its own membership attributes, and the selected policy's groups. For reader mode, additionally provision an unprivileged reader with the attributes listed in the README. Use a group search base containing the domain's groups, including the primary group. Keep the domain's signing and channel-binding requirements enabled. Verify the selected simple-bind transport is compatible; the service does not implement SASL channel binding or relax the domain policy.

Create a test user in a child security group nested inside the service's allowed group. Include separate global, universal, and domain local groups. Record their SIDs and the user's primary group SID. Create another user outside the allowed group. Do not use real production user credentials in tests or CI.

## Run the live probe

Supply a valid service config and a separate exact-byte test-user password file. Add a custom CA only if OS trust is insufficient, and reader credentials only when testing reader mode. Do not commit any secret files.

```sh
export AUTH_AD_CONFIG=/secure/test-auth.yaml
export AUTH_AD_USERNAME='alice@example.com'
export AUTH_AD_PASSWORD_FILE=/secure/alice-password
export AUTH_AD_EXPECT_GROUPS='S-1-5-21-1-2-3-513,S-1-5-21-1-2-3-1101'
export AUTH_AD_POLICY=orders
go test ./integration -run '^TestLiveAD$' -v
```

This opt-in test checks real credential validation and expected primary/nested membership. Optional `AUTH_AD_POLICY` also resolves that policy's named groups and checks authorization. It does not deliberately submit wrong passwords or modify the directory. It prints neither passwords nor directory diagnostics.

## Acceptance matrix

Complete and retain the following environment-specific results:

| Area | Verify |
| --- | --- |
| Account states | Valid password succeeds; wrong password, disabled, locked, expired, password-expired, and password-change-required accounts never reach upstream |
| Membership | Direct, nested, primary, multiple, global, universal, and domain local groups match the recorded SID expectations |
| Group policies | Either allowed group permits access; unrelated groups deny; deny membership overrides allow; each service uses its own policy |
| Changes | SID policies survive renames and reject recreated SIDs; named policies reject a missing old name and follow a recreated same-name group; membership/password changes follow the measured AD replication interval |
| Discovery | Omitted bases and domain SID are discovered correctly; wrong naming context, unexpected domain SID, out-of-domain overrides, and unreadable discovery attributes deny access |
| Named policies | Missing, ambiguous, foreign, distribution, or unreadable allow/deny groups fail closed; only the selected service policy's names are resolved |
| Unsupported results | SID history, unresolved/cross-domain memberships, missing permissions, missing/ranged tokenGroups, and LDAP limits produce closed operational failures |
| Failures | Controller/Global Catalog outage, expired reader secret in reader mode, invalid CA/hostname with default verification, and interrupted/ambiguous binds never cause upstream access; verification bypass occurs only with explicit opt-in |
| Rotation | Reader secret and directory CA rotate through SIGHUP; invalid reload retains the previous working snapshot; listener TLS rotates through restart |
| Deployment | No direct upstream access; untrusted mTLS callers rejected; no credential capture in logs, traces, crash output, or upstream headers |
| Capacity | Measure p50/p95/p99 latency, authentication rate, LDAP phase rate, controller CPU/load, connection churn, saturation, and maximum-replica aggregate limits |

Coordinate invalid-password and lockout tests with the AD owner to avoid locking shared accounts. Agree on a sustainable controller operation budget before enabling general traffic. Record the AD versions, forest/domain functional level, relevant security policies, Go build version, Envoy version, and test load with the results.
