//! Canonical encoding of colon-delimited ACL subject components.
//!
//! Public-edge external identity subjects are colon-delimited, for example
//! `external:logto:<realm>:<organization_id>:<sub>`.  The interpolated
//! components (`realm`, `organization_id`, `sub`) originate from
//! externally-controlled OIDC claims, so a raw `:` inside a component would be
//! indistinguishable from a segment delimiter and could forge an extra segment
//! or a cross-realm subject.
//!
//! [`encode_subject_component`] is the single canonical primitive that escapes
//! the delimiter set so every component maps to a unique, delimiter-free form.
//! Both the subject-construction side (a producer building `external:...`) and
//! the policy/matcher-authoring side MUST encode through this primitive so that
//! derived subjects and ACL policy subjects are byte-equal.
//!
//! Encoding is total and injective: distinct component values always produce
//! distinct encoded forms, so distinct `(realm, organization_id, sub)` tuples
//! always produce distinct subjects.  There is no rejection path; the
//! fail-closed posture is structural (no cross-tuple collision means no forged
//! ACL match) and the matcher's default-deny behaviour is unchanged.

/// Escape a single colon-delimited subject component.
///
/// This is the canonical encoder for one component of a colon-delimited
/// subject.  It escapes exactly the delimiter set:
///
/// - `%` becomes `%25` (the escape character itself)
/// - `:` becomes `%3A` (the segment delimiter)
///
/// Hex digits are uppercase and each input character is examined in a single
/// forward pass, so a literal `"%3A"` in the input encodes to `"%253A"` and can
/// never collide with an encoded `:`.  All other characters pass through
/// unchanged.
///
/// A producer building a subject and the policy author writing the matching
/// subject MUST both route every interpolated component through this function so
/// the two sides are byte-equal.
#[must_use]
pub fn encode_subject_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            ':' => out.push_str("%3A"),
            other => out.push(other),
        }
    }
    out
}

/// Build the canonical public-edge external identity subject
/// `external:logto:<realm>:<organization_id>:<sub>`.
///
/// Each interpolated component is escaped through [`encode_subject_component`]
/// so that a `:` (or the `%` escape) inside `realm`, `organization_id`, or `sub`
/// cannot be confused with a segment delimiter, forge an extra segment, or forge
/// a cross-realm subject.  The `external` prefix and the `logto` provider tag are
/// fixed, trusted literals and are not encoded.
#[must_use]
pub fn encode_external_subject(realm: &str, organization_id: &str, sub: &str) -> String {
    format!(
        "external:logto:{}:{}:{}",
        encode_subject_component(realm),
        encode_subject_component(organization_id),
        encode_subject_component(sub),
    )
}

/// Build the canonical public-edge external organization subject
/// `external:logto:<realm>:<organization_id>`.
///
/// This tier intentionally stops at the organization segment. User subjects
/// always carry one additional encoded `sub` segment, so segment count
/// distinguishes org grants from user grants even when `sub` is empty.
#[must_use]
pub fn encode_external_org_subject(realm: &str, organization_id: &str) -> String {
    format!(
        "external:logto:{}:{}",
        encode_subject_component(realm),
        encode_subject_component(organization_id),
    )
}

/// Build the canonical public-edge external organization-role subject
/// `external:logto:<realm>:<organization_id>:role:<role_name>`.
///
/// `role` is a fixed literal segment. The role name itself is encoded as one
/// component, so a crafted role name cannot shift the realm/org prefix or forge
/// a different role boundary.
#[must_use]
pub fn encode_external_role_subject(realm: &str, organization_id: &str, role_name: &str) -> String {
    format!(
        "external:logto:{}:{}:role:{}",
        encode_subject_component(realm),
        encode_subject_component(organization_id),
        encode_subject_component(role_name),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::valid_subject;

    /// Strict inverse of [`encode_subject_component`], used only to prove the
    /// encoding is injective (round-trips).  Accepts exactly the `%25` and `%3A`
    /// escapes the encoder emits and rejects anything else, fail-closed.
    fn decode_subject_component(s: &str) -> Option<String> {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(ch) = chars.next() {
            if ch == '%' {
                let h1 = chars.next()?;
                let h2 = chars.next()?;
                match (h1, h2) {
                    ('2', '5') => out.push('%'),
                    ('3', 'A') => out.push(':'),
                    _ => return None,
                }
            } else {
                out.push(ch);
            }
        }
        Some(out)
    }

    // 1. A ':' inside `sub` stays inside one segment and cannot forge an extra one.
    #[test]
    fn colon_in_sub_stays_one_segment() {
        let subject = encode_external_subject("r", "org", "a:b");
        let segments: Vec<&str> = subject.split(':').collect();
        assert_eq!(segments, ["external", "logto", "r", "org", "a%3Ab"]);
        assert_eq!(
            decode_subject_component(segments[4]).as_deref(),
            Some("a:b")
        );
    }

    // 2. A crafted `sub` cannot forge a cross-realm subject.
    #[test]
    fn crafted_sub_cannot_forge_cross_realm() {
        let forged = encode_external_subject("realmA", "org", "realmB:o:s");
        let genuine = encode_external_subject("realmB", "o", "s");
        assert_ne!(forged, genuine);
        // The realm stays pinned at its segment regardless of the crafted `sub`.
        assert_eq!(forged.split(':').nth(2), Some("realmA"));
    }

    // 3. A crafted `sub`/`organization_id` cannot shift the org/sub boundary.
    #[test]
    fn crafted_components_preserve_org_sub_boundary() {
        let a = encode_external_subject("r", "a", "b:c");
        let b = encode_external_subject("r", "a:b", "c");
        assert_ne!(a, b);
    }

    // 4. The escape char is itself escaped: a literal "%3A" cannot collide with an
    //    encoded ':'.
    #[test]
    fn escape_char_cannot_collide_with_encoded_delimiter() {
        let literal_percent = encode_external_subject("r", "o", "%3A");
        let literal_colon = encode_external_subject("r", "o", ":");
        assert_ne!(literal_percent, literal_colon);
        assert_eq!(literal_percent.split(':').nth(4), Some("%253A"));
        assert_eq!(literal_colon.split(':').nth(4), Some("%3A"));
    }

    // 5. Encoding is injective: it round-trips for adversarial component values.
    #[test]
    fn encoding_round_trips_for_adversarial_components() {
        for raw in [":", "%", "%3A", "a:b:c", "", "%25", "::%::"] {
            let encoded = encode_subject_component(raw);
            assert!(
                !encoded.contains(':'),
                "encoded form must be delimiter-free: {encoded}"
            );
            assert_eq!(decode_subject_component(&encoded).as_deref(), Some(raw));
        }
    }

    // The encoded subject is accepted by the public subject validator.
    #[test]
    fn encoded_subject_passes_valid_subject() {
        let subject = encode_external_subject("realm-a", "org-1", "alice:smith");
        assert!(valid_subject(&subject));
    }

    #[test]
    fn org_subject_ends_at_org_segment() {
        let subject = encode_external_org_subject("realm:a", "org:b");
        let segments: Vec<&str> = subject.split(':').collect();
        assert_eq!(segments, ["external", "logto", "realm%3Aa", "org%3Ab"]);
    }

    #[test]
    fn role_subject_has_fixed_role_segment() {
        let subject = encode_external_role_subject("realm", "org", "admin:read");
        let segments: Vec<&str> = subject.split(':').collect();
        assert_eq!(
            segments,
            ["external", "logto", "realm", "org", "role", "admin%3Aread"]
        );
    }

    #[test]
    fn empty_sub_user_subject_cannot_collide_with_org_subject() {
        let org_subject = encode_external_org_subject("realm", "org");
        let user_subject = encode_external_subject("realm", "org", "");

        assert_ne!(org_subject, user_subject);
        assert_eq!(org_subject.split(':').count(), 4);
        assert_eq!(user_subject.split(':').count(), 5);
    }

    #[test]
    fn crafted_role_name_cannot_forge_cross_realm_or_org() {
        let crafted = encode_external_role_subject("realm-a", "org-a", "realm-b:org-b:role:admin");
        let genuine = encode_external_role_subject("realm-b", "org-b", "admin");

        assert_ne!(crafted, genuine);
        let segments: Vec<&str> = crafted.split(':').collect();
        assert_eq!(
            &segments[..5],
            ["external", "logto", "realm-a", "org-a", "role"]
        );
        assert_eq!(
            decode_subject_component(segments[5]).as_deref(),
            Some("realm-b:org-b:role:admin")
        );
    }

    #[test]
    fn crafted_sub_cannot_collide_with_org_or_role_subjects() {
        let crafted_user = encode_external_subject("realm", "org", "role:admin");
        let role_subject = encode_external_role_subject("realm", "org", "admin");
        let org_subject = encode_external_org_subject("realm", "org");

        assert_ne!(crafted_user, role_subject);
        assert_ne!(crafted_user, org_subject);
        assert_eq!(crafted_user.split(':').count(), 5);
        assert_eq!(role_subject.split(':').count(), 6);
        assert_eq!(org_subject.split(':').count(), 4);
    }
}
