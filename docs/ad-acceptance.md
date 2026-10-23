# Active Directory acceptance

Run against a disposable AD DS domain before production. Unit tests use LDAP response fixtures; the real Envoy test also uses a fixture directory. Neither replaces these checks.

## Fixture

Provision an unprivileged reader with the attributes listed in the README, two LDAPS controllers, and Global Catalog availability. Use a group search base containing the domain's groups, including the primary group. Keep the domain's signing and channel-binding requirements enabled. Verify the selected simple-bind transport is compatible; the service does not implement SASL channel binding or relax the domain policy.

Create a test user in a child security group nested inside the service's allowed group. Include separate global, universal, and domain local groups. Record their SIDs and the user's primary group SID. Create another user outside the allowed group. Do not use real production user credentials in tests or CI.

## Run the live probe

Supply a valid service config with local CA/reader-secret paths and a separate exact-byte test-user password file. Do not commit any secret files.

```sh
export AUTH_AD_CONFIG=/secure/test-auth.yaml
export AUTH_AD_USERNAME='alice@example.com'
export AUTH_AD_PASSWORD_FILE=/secure/alice-password
export AUTH_AD_EXPECT_GROUPS='S-1-5-21-1-2-3-513,S-1-5-21-1-2-3-1101'
go test ./integration -run '^TestLiveAD$' -v
```

This opt-in test checks real credential validation and expected primary/nested membership. It does not deliberately submit wrong passwords or modify the directory. It prints neither passwords nor directory diagnostics.

## Acceptance matrix

Complete and retain the following environment-specific results:

| Area | Verify |
| --- | --- |
| Account states | Valid password succeeds; wrong password, disabled, locked, expired, password-expired, and password-change-required accounts never reach upstream |
| Membership | Direct, nested, primary, multiple, global, universal, and domain local groups match the recorded SID expectations |
| Group policies | Either allowed group permits access; unrelated groups deny; deny membership overrides allow; each service uses its own policy |
| Changes | Rename keeps access, recreated group with a new SID does not inherit access, membership/password changes propagate within the measured AD replication interval |
| Unsupported results | SID history, unresolved/cross-domain memberships, missing permissions, missing/ranged tokenGroups, and LDAP limits produce closed operational failures |
| Failures | Controller/Global Catalog outage, expired reader secret, invalid CA/hostname, and interrupted/ambiguous binds never cause upstream access |
| Rotation | Reader secret and directory CA rotate through SIGHUP; invalid reload retains the previous working snapshot; listener TLS rotates through restart |
| Deployment | No direct upstream access; untrusted mTLS callers rejected; no credential capture in logs, traces, crash output, or upstream headers |
| Capacity | Measure p50/p95/p99 latency, authentication rate, LDAP phase rate, controller CPU/load, connection churn, saturation, and maximum-replica aggregate limits |

Coordinate invalid-password and lockout tests with the AD owner to avoid locking shared accounts. Agree on a sustainable controller operation budget before enabling general traffic. Record the AD versions, forest/domain functional level, relevant security policies, Go build version, Envoy version, and test load with the results.
