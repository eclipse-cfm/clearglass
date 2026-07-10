# clearglass

ClearGlass is a small authentication service for Traefik (`ForwardAuth`) that validates Bearer tokens
against the issuer's JWKS and enforces OAuth2 scope requirements.

## How it works

Traefik forwards every inbound request to `GET /validate` with the original `Authorization` header
plus `X-Forwarded-Method` / `X-Forwarded-Uri`. clearglass answers:

- `200` — token is valid and satisfies the scope requirements
- `401` — missing or invalid token
- `403` — token is valid but lacks the required scopes

Scope requirements come from two sources:

1. **Legacy `?scope=` query params** on the middleware URL (`/validate?scope=a&scope=b`): the token
   must carry at least one of them **verbatim**. This is the pre-route-map mechanism and will be
   removed once all deployments use the route map.
2. **A static route→scope map** (`ROUTES_FILE`): method- and path-aware rules evaluated against
   `X-Forwarded-Method` / `X-Forwarded-Uri`. See [routes.example.yaml](routes.example.yaml).

## Route map

```yaml
default: deny            # deny | allow — applies when no rule matches
routes:
  - path: /api/identity/participants/*/credentials/**
    methods: [GET]       # omit to match any method
    anyOf: [identity-api:credentials:read]
```

- Rules are evaluated top to bottom; the **first** rule whose method and path match decides.
  Order the file most-specific-first.
- Path patterns are segment globs: `*` matches exactly one segment, `**` (final segment only)
  matches any remainder.
- `anyOf` is satisfied when the token carries at least one scope that **implies** one of the listed
  scopes, following the EDC scope grammar `<api>:[<resource>:]<action>`:
  - actions form a hierarchy: `admin ⊇ write ⊇ read`
  - api-level (`identity-api:read`) and wildcard (`identity-api:*:read`) scopes cover any
    resource-level requirement (`identity-api:participants:read`); the reverse does not hold
  - scopes outside the grammar only match exactly

  Rules should therefore name the **narrowest sufficient scope**; coarser tokens keep working.

### Rollout: report-only vs enforce

With `ENFORCE_ROUTES=false` (the default), route-map violations are only logged
(`report-only: ... would be denied with ENFORCE_ROUTES=true`) and the legacy `?scope=` check alone
decides. Run in this mode first, watch the logs for would-be denials, fix the rule file, then set
`ENFORCE_ROUTES=true`.

## Configuration

| Env var          | Required | Default | Purpose                                                        |
|------------------|----------|---------|----------------------------------------------------------------|
| `JWKS_URL`       | yes      | —       | JWKS endpoint used to verify token signatures                  |
| `PORT`           | no       | `8080`  | Listen port                                                    |
| `ROUTES_FILE`    | no       | —       | Path to the route→scope map (YAML); unset = legacy checks only |
| `ENFORCE_ROUTES` | no       | `false` | `true` = route map denials are enforced; else report-only      |

## Development

```shell
cargo build
cargo test
```
