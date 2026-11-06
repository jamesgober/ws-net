//! The budget audit: every place the crate's own code grows the heap names
//! the budget that bounds it, in a `// budget: <guard>` note earlier in the
//! same function. A new growth site without a note, or a note naming no
//! known guard, fails this test, so each one is reviewed when it is added.
//!
//! The guards:
//!
//! - `max_message`: `Limits::max_message` (reassembly, delivered messages).
//! - `max_output`: `Limits::max_output`, plus the 262-byte headroom for the
//!   automatic Pong and Close.
//! - `input_buffer`: `Limits::input_buffer`.
//! - `max_head`: `ServerHandshake::MAX_HEAD`, the opening handshake's head.
//! - `fixed`: a constant size.
//! - `capacity`: writes within capacity already allocated; never grows.
//! - `caller`: sized by the caller's own arguments or configuration, never
//!   by the peer.
//!
//! The scan is textual (the growth calls of `Vec` and `String`, `vec!`,
//! `format!`, `to_vec`, `to_string`, `collect`) over `src/`, up to each
//! file's test module.

use std::{collections::BTreeMap, fs, path::Path};

const GUARDS: &[&str] = &[
    "max_message",
    "max_output",
    "input_buffer",
    "max_head",
    "fixed",
    "capacity",
    "caller",
];

const GROWTH: &[&str] = &[
    ".push(",
    ".push_str(",
    ".extend_from_slice(",
    ".extend(",
    ".reserve(",
    ".reserve_exact(",
    ".try_reserve(",
    ".try_reserve_exact(",
    ".resize(",
    ".insert(",
    ".append(",
    "with_capacity(",
    "vec![",
    ".to_vec()",
    ".to_owned()",
    "String::from(",
    "format!(",
    ".collect()",
    ".collect::<",
    ".to_string()",
    "Box::new(",
    "Vec::from(",
];

/// Whether `line` starts a function.
fn starts_fn(line: &str) -> bool {
    let mut rest = line.trim_start();
    for prefix in ["pub(crate) ", "pub ", "const ", "unsafe "] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }
    rest.starts_with("fn ")
}

/// The guard a `// budget:` note names, if the line is one.
fn note(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("// budget: ")?;
    let end = rest.find([':', '.', ' ']).unwrap_or(rest.len());
    Some(&rest[..end])
}

#[test]
fn test_budget_audit_every_growth_site_names_its_guard() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files: Vec<_> = fs::read_dir(&src)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    let mut missing = Vec::new();
    let mut unknown = Vec::new();
    let mut by_guard: BTreeMap<&str, usize> = BTreeMap::new();
    let mut sites = 0;
    let texts: Vec<_> = files
        .iter()
        .map(|f| {
            (
                f.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(f).unwrap(),
            )
        })
        .collect();
    for (name, text) in &texts {
        let mut guard: Option<&str> = None;
        for (i, line) in text.lines().enumerate() {
            if line.starts_with("#[cfg(test)]") {
                break;
            }
            if starts_fn(line) {
                guard = None;
            }
            if let Some(g) = note(line) {
                if GUARDS.contains(&g) {
                    guard = Some(g);
                } else {
                    unknown.push(format!("{name}:{}: {g}", i + 1));
                }
                continue;
            }
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if GROWTH.iter().any(|g| code.contains(g)) {
                sites += 1;
                match guard {
                    Some(g) => *by_guard.entry(g).or_default() += 1,
                    None => missing.push(format!("{name}:{}: {}", i + 1, code)),
                }
            }
        }
    }
    println!("{sites} growth sites: {by_guard:?}");
    assert!(
        unknown.is_empty(),
        "budget notes naming no known guard:\n{}",
        unknown.join("\n")
    );
    assert!(
        missing.is_empty(),
        "growth sites without a `// budget:` note in their function:\n{}",
        missing.join("\n")
    );
    // The scan itself still finds the sites (a broken pattern would pass
    // vacuously).
    assert!(sites > 50, "only {sites} growth sites found");
    for g in ["max_message", "max_output", "input_buffer", "max_head"] {
        assert!(by_guard.contains_key(g), "no site guarded by {g}");
    }
}
