// Copyright (c) 2026 Metaform Systems, Inc.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License, Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0
//
// Contributors:
//      Metaform Systems, Inc. - initial API and implementation

//! Scope implication following the EDC scope grammar `<api>:[<resource>:]<action>`
//! with `action ∈ {read, write, admin}`.
//!
//! A presented scope satisfies a required scope when it is equal or wider:
//!   - actions form a hierarchy: `admin ⊇ write ⊇ read`
//!   - an api-level scope (`identity-api:read`) or a resource wildcard
//!     (`identity-api:*:read`) covers any resource-level requirement
//!     (`identity-api:participants:read`)
//!   - a resource-level scope does NOT satisfy an api-level requirement
//!
//! Scopes that do not follow the grammar (e.g. plain `read`) only match exactly.
//! These rules must stay aligned with the enforcement inside the EDC services.

fn action_rank(action: &str) -> Option<u8> {
    match action {
        "read" => Some(1),
        "write" => Some(2),
        "admin" => Some(3),
        _ => None,
    }
}

struct ParsedScope<'a> {
    api: &'a str,
    resource: Option<&'a str>,
    rank: u8,
}

fn parse(scope: &str) -> Option<ParsedScope<'_>> {
    let parts: Vec<&str> = scope.split(':').collect();
    match parts.as_slice() {
        [api, action] if !api.is_empty() => action_rank(action).map(|rank| ParsedScope {
            api,
            resource: None,
            rank,
        }),
        [api, resource, action] if !api.is_empty() && !resource.is_empty() => action_rank(action)
            .map(|rank| ParsedScope {
                api,
                resource: Some(resource),
                rank,
            }),
        _ => None,
    }
}

/// Does `presented` cover the resource segment demanded by `required`?
fn resource_covers(presented: Option<&str>, required: Option<&str>) -> bool {
    match presented {
        // api-level and wildcard scopes cover every resource of that api
        None | Some("*") => true,
        // a concrete resource only covers exactly that resource
        Some(p) => matches!(required, Some(r) if p == r),
    }
}

/// Returns true when the `presented` scope satisfies the `required` scope.
pub fn satisfies(presented: &str, required: &str) -> bool {
    if presented == required {
        return true;
    }
    let (Some(p), Some(r)) = (parse(presented), parse(required)) else {
        return false;
    };
    p.api == r.api && p.rank >= r.rank && resource_covers(p.resource, r.resource)
}

/// Returns true when any of the `presented` scopes satisfies any of the `required` scopes.
pub fn any_satisfies<'a>(
    presented: impl Iterator<Item = &'a str> + Clone,
    required: &[String],
) -> bool {
    required
        .iter()
        .any(|r| presented.clone().any(|p| satisfies(p, r)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_always_satisfies() {
        assert!(satisfies("identity-api:read", "identity-api:read"));
        // non-grammar scopes match exactly, nothing more
        assert!(satisfies("cfm-read", "cfm-read"));
        assert!(!satisfies("cfm-read", "cfm-write"));
        assert!(!satisfies("read", "identity-api:read"));
    }

    #[test]
    fn action_hierarchy() {
        assert!(satisfies("identity-api:write", "identity-api:read"));
        assert!(satisfies("identity-api:admin", "identity-api:read"));
        assert!(satisfies("identity-api:admin", "identity-api:write"));
        assert!(!satisfies("identity-api:read", "identity-api:write"));
        assert!(!satisfies("identity-api:write", "identity-api:admin"));
    }

    #[test]
    fn api_level_covers_resource_level() {
        assert!(satisfies(
            "identity-api:read",
            "identity-api:participants:read"
        ));
        assert!(satisfies(
            "identity-api:write",
            "identity-api:participants:read"
        ));
        assert!(satisfies(
            "identity-api:admin",
            "identity-api:participants:write"
        ));
    }

    #[test]
    fn wildcard_resource_covers_specific_and_api_level() {
        assert!(satisfies(
            "identity-api:*:read",
            "identity-api:participants:read"
        ));
        assert!(satisfies("identity-api:*:read", "identity-api:read"));
        assert!(satisfies("identity-api:*:write", "identity-api:dids:read"));
    }

    #[test]
    fn resource_level_does_not_widen() {
        assert!(!satisfies(
            "identity-api:participants:read",
            "identity-api:read"
        ));
        assert!(!satisfies(
            "identity-api:participants:read",
            "identity-api:*:read"
        ));
        assert!(!satisfies(
            "identity-api:participants:write",
            "identity-api:dids:write"
        ));
    }

    #[test]
    fn same_resource_action_hierarchy() {
        assert!(satisfies(
            "identity-api:participants:write",
            "identity-api:participants:read"
        ));
        assert!(!satisfies(
            "identity-api:participants:read",
            "identity-api:participants:write"
        ));
    }

    #[test]
    fn apis_do_not_cross() {
        assert!(!satisfies("management-api:admin", "identity-api:read"));
        assert!(!satisfies("identity-api:admin", "issuer-admin-api:read"));
    }

    #[test]
    fn malformed_scopes_never_widen() {
        assert!(!satisfies("identity-api:", "identity-api:read"));
        assert!(!satisfies(":read", "identity-api:read"));
        assert!(!satisfies("identity-api:foo", "identity-api:read"));
        assert!(!satisfies("identity-api:a:b:read", "identity-api:read"));
    }

    #[test]
    fn any_satisfies_over_sets() {
        let required = vec!["identity-api:participants:read".to_string()];
        assert!(any_satisfies(
            ["foo", "identity-api:read"].into_iter(),
            &required
        ));
        assert!(!any_satisfies(["foo", "bar"].into_iter(), &required));
        assert!(!any_satisfies([].into_iter(), &required));
    }
}
