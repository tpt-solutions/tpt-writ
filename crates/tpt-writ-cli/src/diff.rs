//! `writ diff` — the capability security-regression view.
//!
//! Same question as `nexus diff`: did the resource-access surface widen?
//! Exit 0 = no change or a narrowing; exit 1 = a widening (a new `Write`,
//! or `Pure` → `Read`/`Write`, or a new function earning any access right).

use std::collections::BTreeMap;

use tpt_writ_core::WritRight;

/// How one function's right moved from the before-source to the after-source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delta {
    /// Function exists in both, right unchanged.
    Unchanged(String),
    /// Function exists in both, right changed without widening.
    Changed { before: WritRight, after: WritRight },
    /// The right grew strictly more permissive — the security regression.
    Widened { before: WritRight, after: WritRight },
    /// The right shrank — an improvement, never a regression.
    Narrowed { before: WritRight, after: WritRight },
    /// New function in the after-source with no resource access (`Pure`).
    AddedPure(String),
    /// New function in the after-source that can touch resources.
    AddedWithAccess(String),
    /// Function disappeared; it holds nothing anymore.
    Removed(String),
}

/// Classify every function across the two derived tables.
pub fn classify(
    before: &BTreeMap<String, WritRight>,
    after: &BTreeMap<String, WritRight>,
) -> Vec<(String, Delta)> {
    use Delta::*;
    let mut out = Vec::new();
    for (name, b) in before {
        match after.get(name) {
            Some(a) if a == b => out.push((name.clone(), Unchanged(name.clone()))),
            Some(a) => out.push((name.clone(), classify_pair(b, a))),
            None => out.push((name.clone(), Removed(name.clone()))),
        }
    }
    for (name, a) in after {
        if !before.contains_key(name) {
            out.push((
                name.clone(),
                if a == &WritRight::Pure {
                    AddedPure(name.clone())
                } else {
                    AddedWithAccess(name.clone())
                },
            ));
        }
    }
    out.sort_by(|l, r| l.0.cmp(&r.0));
    out
}

fn classify_pair(b: &WritRight, a: &WritRight) -> Delta {
    use Delta::{Changed, Narrowed, Widened};

    let widened = match (b, a) {
        // Any coarse fallback outranks every scoped right and Pure.
        (_, WritRight::Write { resource_class: ac }) if ac == "*" => b != a,
        // Pure is the floor: anything above it widens.
        (WritRight::Pure, _) => !matches!(a, WritRight::Pure),
        // Gaining write over an existing read widens, whatever the classes.
        (WritRight::Read { .. }, WritRight::Write { .. }) => true,
        _ => false,
    };
    let narrowed = match (b, a) {
        // Losing the coarse fallback is always an improvement.
        (WritRight::Write { resource_class: bc }, _) if bc == "*" => a != b,
        // Retreating to Pure sheds all access.
        (_, WritRight::Pure) => !matches!(b, WritRight::Pure),
        // Dropping write access (keeping at most a read) narrows, whatever
        // happens to the class.
        (WritRight::Write { .. }, WritRight::Read { .. }) => true,
        // Swapping one scoped write for another moves sideways.
        _ => false,
    };

    match (widened, narrowed) {
        (true, false) => Widened {
            before: b.clone(),
            after: a.clone(),
        },
        (false, true) => Narrowed {
            before: b.clone(),
            after: a.clone(),
        },
        // Cross-class swaps without a mode change (Read{fs} -> Read{db},
        // Write{fs} -> Write{db}) move sideways: report as a change, not a
        // regression — nothing held before is still held now *and more*.
        _ => Changed {
            before: b.clone(),
            after: a.clone(),
        },
    }
}

/// True when any delta is [`Delta::Widened`] or [`Delta::AddedWithAccess`].
pub fn any_widening(deltas: &[(String, Delta)]) -> bool {
    deltas
        .iter()
        .any(|(_, d)| matches!(d, Delta::Widened { .. } | Delta::AddedWithAccess(_)))
}

/// Render the human-readable delta table.
pub fn format_deltas(deltas: &[(String, Delta)]) -> String {
    deltas
        .iter()
        .map(|(name, d)| match d {
            Delta::Unchanged(_) => format!("  = {name}: unchanged"),
            Delta::Changed { before, after } => {
                format!("  ~ {name}: {before} -> {after} (sideways)")
            }
            Delta::Widened { before, after } => {
                format!("  ! {name}: {before} -> {after} (WIDENED)")
            }
            Delta::Narrowed { before, after } => {
                format!("  - {name}: {before} -> {after} (narrowed)")
            }
            Delta::AddedPure(name) => format!("  = +{name}: Pure (no access)"),
            Delta::AddedWithAccess(name) => format!("  ! +{name}: new access right (WIDENED)"),
            Delta::Removed(name) => format!("  - -{name}: removed"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rights(pairs: &[(&str, WritRight)]) -> BTreeMap<String, WritRight> {
        pairs
            .iter()
            .map(|(n, r)| ((*n).to_string(), r.clone()))
            .collect()
    }

    fn pure() -> WritRight {
        WritRight::Pure
    }
    fn read(c: &str) -> WritRight {
        WritRight::Read {
            resource_class: c.into(),
        }
    }
    fn write(c: &str) -> WritRight {
        WritRight::Write {
            resource_class: c.into(),
        }
    }

    #[test]
    fn identical_tables_have_no_widening() {
        let t = rights(&[("f", pure()), ("g", write("*"))]);
        let deltas = classify(&t, &t);
        assert!(!any_widening(&deltas));
    }

    #[test]
    fn pure_to_write_is_widening() {
        let b = rights(&[("f", pure())]);
        let a = rights(&[("f", write("*"))]);
        assert!(any_widening(&classify(&b, &a)));
    }

    #[test]
    fn pure_to_read_is_widening() {
        let b = rights(&[("f", pure())]);
        let a = rights(&[("f", read("fs"))]);
        assert!(any_widening(&classify(&b, &a)));
    }

    #[test]
    fn read_to_scoped_write_is_widening() {
        let b = rights(&[("f", read("fs:/data"))]);
        let a = rights(&[("f", write("fs:/data"))]);
        assert!(any_widening(&classify(&b, &a)));
    }

    #[test]
    fn scoped_write_to_coarse_write_is_widening() {
        let b = rights(&[("f", write("fs:/data"))]);
        let a = rights(&[("f", write("*"))]);
        assert!(any_widening(&classify(&b, &a)));
    }

    #[test]
    fn read_to_any_write_is_widening_even_cross_class() {
        let b = rights(&[("f", read("fs:/data"))]);
        let a = rights(&[("f", write("db:users"))]);
        assert!(any_widening(&classify(&b, &a)));
    }

    #[test]
    fn new_function_with_access_is_widening_but_pure_is_not() {
        let b = rights(&[("old", pure())]);
        let a = rights(&[("old", pure()), ("new_tool", write("*"))]);
        assert!(any_widening(&classify(&b, &a)));

        let a2 = rights(&[("old", pure()), ("new_pure", pure())]);
        assert!(!any_widening(&classify(&b, &a2)));
    }

    #[test]
    fn narrowings_are_never_widenings() {
        // coarse -> scoped write
        let b = rights(&[("f", write("*"))]);
        let a = rights(&[("f", write("db:users"))]);
        let d = classify(&b, &a);
        assert!(!any_widening(&d));

        // scoped write -> pure
        let b = rights(&[("f", write("fs"))]);
        let a = rights(&[("f", pure())]);
        assert!(!any_widening(&classify(&b, &a)));

        // any write -> any read
        let b = rights(&[("f", write("fs"))]);
        let a = rights(&[("f", read("fs"))]);
        assert!(!any_widening(&classify(&b, &a)));
    }

    #[test]
    fn removing_a_function_narrows() {
        let b = rights(&[("gone", write("*")), ("kept", pure())]);
        let a = rights(&[("kept", pure())]);
        let deltas = classify(&b, &a);
        assert!(!any_widening(&deltas));
        assert!(deltas
            .iter()
            .any(|(n, d)| n == "gone" && matches!(d, Delta::Removed(_))));
    }

    #[test]
    fn cross_class_same_mode_moves_sideways_without_regression() {
        let b = rights(&[("f", read("fs"))]);
        let a = rights(&[("f", read("db"))]);
        let deltas = classify(&b, &a);
        assert!(!any_widening(&deltas));
        assert!(matches!(&deltas[0].1, Delta::Changed { .. }));
    }
}
