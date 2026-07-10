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

//! Static route→scope map.
//!
//! A YAML file declares which scopes a request needs, by method and path:
//!
//! ```yaml
//! default: deny            # deny | allow — applies when no rule matches
//! routes:
//!   - path: /api/identity/v1beta/participants/*/credentials/**
//!     methods: [GET]       # omit to match any method
//!     anyOf: [identity-api:credentials:read]
//! ```
//!
//! Path patterns are segment globs: `*` matches exactly one segment, `**`
//! (final segment only) matches any remainder including nothing. Rules are
//! evaluated top to bottom; the FIRST rule whose method and path match decides,
//! so order the file most-specific-first. `anyOf` is satisfied when the token
//! carries at least one scope that satisfies (see `scopes::satisfies`) one of
//! the listed scopes — rules should therefore name the narrowest sufficient
//! scope and rely on implication for wider tokens.

use crate::scopes;
use serde::Deserialize;
use std::fs;

type Error = Box<dyn std::error::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub path: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(rename = "anyOf")]
    pub any_of: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    #[serde(default)]
    pub default: DefaultAction,
    pub routes: Vec<Route>,
}

/// Outcome of evaluating a request against the route map.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// A rule matched and the token satisfies it, or no rule matched and default is allow.
    Allow,
    /// A rule matched but the token does not satisfy its scopes.
    InsufficientScope {
        rule_path: String,
        required: Vec<String>,
    },
    /// No rule matched and the default is deny.
    NoMatchingRule,
}

impl RouteConfig {
    pub fn load(path: &str) -> Result<Self, Error> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read routes file {path}: {e}"))?;
        let config: RouteConfig = serde_yaml_ng::from_str(&raw)
            .map_err(|e| format!("failed to parse routes file {path}: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        for (i, route) in self.routes.iter().enumerate() {
            if !route.path.starts_with('/') {
                return Err(format!("route[{i}] path must start with '/': {}", route.path).into());
            }
            if route.any_of.is_empty() {
                return Err(format!("route[{i}] anyOf must not be empty: {}", route.path).into());
            }
            let segments: Vec<&str> = route.path.trim_matches('/').split('/').collect();
            if let Some(pos) = segments.iter().position(|s| *s == "**") {
                if pos != segments.len() - 1 {
                    return Err(format!(
                        "route[{i}] '**' is only allowed as the final segment: {}",
                        route.path
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    /// Evaluates `method` and `path` (no query string) against the rules,
    /// checking required scopes against the space-separated token `scope` claim.
    pub fn evaluate(&self, method: &str, path: &str, token_scopes: &str) -> Decision {
        for route in &self.routes {
            if !method_matches(&route.methods, method) || !path_matches(&route.path, path) {
                continue;
            }
            return if scopes::any_satisfies(token_scopes.split_whitespace(), &route.any_of) {
                Decision::Allow
            } else {
                Decision::InsufficientScope {
                    rule_path: route.path.clone(),
                    required: route.any_of.clone(),
                }
            };
        }
        match self.default {
            DefaultAction::Allow => Decision::Allow,
            DefaultAction::Deny => Decision::NoMatchingRule,
        }
    }
}

fn method_matches(allowed: &[String], method: &str) -> bool {
    allowed.is_empty() || allowed.iter().any(|m| m.eq_ignore_ascii_case(method))
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern_segs: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_segs: Vec<&str> = path.trim_matches('/').split('/').collect();

    let mut pi = 0;
    for (i, pseg) in pattern_segs.iter().enumerate() {
        if *pseg == "**" {
            // final segment (enforced at load time): matches any remainder
            debug_assert!(i == pattern_segs.len() - 1);
            return true;
        }
        let Some(seg) = path_segs.get(pi) else {
            return false;
        };
        if *pseg != "*" && pseg != seg {
            return false;
        }
        pi += 1;
    }
    pi == path_segs.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> RouteConfig {
        let config: RouteConfig = serde_yaml_ng::from_str(yaml).expect("yaml parse failed");
        config.validate().expect("validation failed");
        config
    }

    const SAMPLE: &str = r#"
default: deny
routes:
  - path: /api/identity/v1beta/participants/*/credentials/**
    methods: [GET]
    anyOf: [identity-api:credentials:read]
  - path: /api/identity/v1beta/participants/*/credentials/**
    methods: [POST]
    anyOf: [identity-api:credentials:write]
  - path: /api/identity/v1beta/participants/**
    methods: [POST, DELETE]
    anyOf: [identity-api:participants:write]
  - path: /api/identity/**
    methods: [GET]
    anyOf: [identity-api:read]
  - path: /public/health
    anyOf: [does-not-matter]
"#;

    #[test]
    fn path_glob_semantics() {
        assert!(path_matches("/a/b", "/a/b"));
        assert!(path_matches("/a/b/", "/a/b"));
        assert!(!path_matches("/a/b", "/a"));
        assert!(!path_matches("/a", "/a/b"));

        // `*` — exactly one segment
        assert!(path_matches("/a/*/c", "/a/b/c"));
        assert!(!path_matches("/a/*/c", "/a/c"));
        assert!(!path_matches("/a/*/c", "/a/b/d/c"));

        // `**` — any remainder, including nothing
        assert!(path_matches("/a/**", "/a"));
        assert!(path_matches("/a/**", "/a/b/c"));
        assert!(!path_matches("/a/**", "/b"));
    }

    #[test]
    fn first_match_wins_and_methods_filter() {
        let c = config(SAMPLE);
        // GET credentials → credentials:read rule, api-level token satisfies via implication
        assert_eq!(
            c.evaluate(
                "GET",
                "/api/identity/v1beta/participants/p1/credentials",
                "identity-api:read"
            ),
            Decision::Allow
        );
        // narrow token on the exact rule
        assert_eq!(
            c.evaluate(
                "GET",
                "/api/identity/v1beta/participants/p1/credentials/request/r1",
                "identity-api:credentials:read"
            ),
            Decision::Allow
        );
        // POST credentials needs write; read token fails on that rule (not the GET one)
        assert_eq!(
            c.evaluate(
                "POST",
                "/api/identity/v1beta/participants/p1/credentials",
                "identity-api:credentials:read"
            ),
            Decision::InsufficientScope {
                rule_path: "/api/identity/v1beta/participants/*/credentials/**".into(),
                required: vec!["identity-api:credentials:write".into()],
            }
        );
        // POST on participants root → participants:write rule
        assert_eq!(
            c.evaluate(
                "POST",
                "/api/identity/v1beta/participants",
                "identity-api:participants:write"
            ),
            Decision::Allow
        );
        // method case-insensitive
        assert_eq!(
            c.evaluate(
                "post",
                "/api/identity/v1beta/participants",
                "identity-api:admin"
            ),
            Decision::Allow
        );
    }

    #[test]
    fn default_deny_when_no_rule_matches() {
        let c = config(SAMPLE);
        assert_eq!(
            c.evaluate(
                "DELETE",
                "/api/identity/v1beta/keypairs",
                "identity-api:admin"
            ),
            Decision::NoMatchingRule
        );
        assert_eq!(
            c.evaluate("GET", "/api/other", "identity-api:admin"),
            Decision::NoMatchingRule
        );
    }

    #[test]
    fn default_allow_when_configured() {
        let c = config("default: allow\nroutes: []");
        assert_eq!(c.evaluate("GET", "/anything", ""), Decision::Allow);
    }

    #[test]
    fn rule_without_methods_matches_any_method() {
        let c = config(SAMPLE);
        assert_eq!(
            c.evaluate("PATCH", "/public/health", "does-not-matter"),
            Decision::Allow
        );
    }

    #[test]
    fn validation_rejects_bad_rules() {
        let no_slash: RouteConfig =
            serde_yaml_ng::from_str("routes:\n  - path: api/x\n    anyOf: [a]").unwrap();
        assert!(no_slash.validate().is_err());

        let empty_scopes: RouteConfig =
            serde_yaml_ng::from_str("routes:\n  - path: /api/x\n    anyOf: []").unwrap();
        assert!(empty_scopes.validate().is_err());

        let inner_glob: RouteConfig =
            serde_yaml_ng::from_str("routes:\n  - path: /api/**/x\n    anyOf: [a]").unwrap();
        assert!(inner_glob.validate().is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let result: Result<RouteConfig, _> =
            serde_yaml_ng::from_str("routes:\n  - path: /a\n    anyOf: [x]\n    scopes: [y]");
        assert!(result.is_err());
    }
}
