#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Checks `kat/kat-v0.2-conformance-manifest.json`, the map from the
//! requirements of `docs/specs.md` to the conformance vectors and to the
//! tests of the reference implementation:
//!
//! * every section anchor, vector pointer, test, script and audit identifier
//!   it names exists;
//! * every normative section of the specification, every vector section and
//!   every signed-object vector is covered by a requirement;
//! * every test of `cityg-core` is mapped to a requirement.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value as Json;

const MANIFEST: &str = "kat/kat-v0.2-conformance-manifest.json";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn load_json(relative: &str) -> Json {
    serde_json::from_str(&read(&repo().join(relative)))
        .unwrap_or_else(|err| panic!("{relative}: {err}"))
}

fn strings(value: &Json, field: &str, owner: &str) -> Vec<String> {
    match value.get(field) {
        None => Vec::new(),
        Some(Json::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .unwrap_or_else(|| panic!("{owner}: {field} holds strings"))
                    .to_owned()
            })
            .collect(),
        Some(_) => panic!("{owner}: {field} is an array"),
    }
}

/// `<a id="...">` anchors of the specification.
fn spec_anchors(spec: &str) -> BTreeSet<String> {
    spec.match_indices("<a id=\"")
        .map(|(start, marker)| {
            let rest = &spec[start + marker.len()..];
            rest[..rest.find('"').expect("closed anchor")].to_owned()
        })
        .collect()
}

/// Finding and proposal identifiers of the audit report (`### C-01 — ...`).
fn audit_ids(report: &str) -> BTreeSet<String> {
    report
        .lines()
        .filter_map(|line| line.strip_prefix("### "))
        .filter_map(|title| title.split_whitespace().next())
        .filter(|id| {
            let mut parts = id.split('-');
            matches!(
                (parts.next(), parts.next(), parts.next()),
                (Some("C" | "H" | "M" | "L" | "P"), Some(number), None)
                    if !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
            )
        })
        .map(str::to_owned)
        .collect()
}

/// Resolve `/json/pointer` or `/json/pointer#id` in the vector file.
fn resolve_vector<'a>(vectors: &'a Json, reference: &str) -> Result<&'a Json, String> {
    let (pointer, id) = match reference.split_once('#') {
        Some((pointer, id)) => (pointer, Some(id)),
        None => (reference, None),
    };
    let target = vectors
        .pointer(pointer)
        .ok_or_else(|| format!("no vector at {pointer}"))?;
    match id {
        None => Ok(target),
        Some(id) => target
            .as_array()
            .and_then(|items| items.iter().find(|item| item["id"] == id))
            .ok_or_else(|| format!("no vector with id {id} in {pointer}")),
    }
}

/// Root source file of a nextest binary id: `crate` (library unit tests),
/// `crate::bin/name` (binary unit tests) or `crate::name` (integration test).
fn binary_root(binary: &str) -> Result<PathBuf, String> {
    let crates = repo().join("crates");
    let root = match binary.split_once("::") {
        None => crates.join(binary).join("src/lib.rs"),
        Some((krate, rest)) => match rest.strip_prefix("bin/") {
            Some(name) if name == krate => crates.join(krate).join("src/main.rs"),
            Some(name) => crates
                .join(krate)
                .join("src/bin")
                .join(format!("{name}.rs")),
            None => crates.join(krate).join("tests").join(format!("{rest}.rs")),
        },
    };
    if root.is_file() {
        Ok(root)
    } else {
        Err(format!("no source {} for binary {binary}", root.display()))
    }
}

/// Whether `source` declares module `name`, inline (`Some(true)`) or in its
/// own file (`Some(false)`).
fn declares_module(source: &str, name: &str) -> Option<bool> {
    source.lines().find_map(|line| {
        let line = line.trim_start();
        let line = ["pub(crate) ", "pub(super) ", "pub "]
            .iter()
            .find_map(|visibility| line.strip_prefix(visibility))
            .unwrap_or(line);
        let rest = line.strip_prefix("mod ")?.strip_prefix(name)?.trim_start();
        if rest.starts_with('{') {
            Some(true)
        } else if rest.starts_with(';') {
            Some(false)
        } else {
            None
        }
    })
}

/// Source file that holds the test `path` (`module::...::function`) of the
/// binary rooted at `root`, following Rust's module file layout.
fn test_file(root: &Path, modules: &[&str]) -> Result<PathBuf, String> {
    let mut file = root.to_path_buf();
    // Directory holding the child modules of the current module.
    let mut dir = root.parent().expect("root has a parent").to_path_buf();
    for module in modules {
        let source = read(&file);
        match declares_module(&source, module) {
            Some(true) => dir.push(module),
            Some(false) => {
                let flat = dir.join(format!("{module}.rs"));
                let nested = dir.join(module).join("mod.rs");
                file = if flat.is_file() {
                    flat
                } else if nested.is_file() {
                    nested
                } else {
                    return Err(format!("no file for module {module} in {}", dir.display()));
                };
                dir.push(module);
            }
            None => {
                return Err(format!("{} declares no module {module}", file.display()));
            }
        }
    }
    Ok(file)
}

fn is_test_attribute(line: &str) -> bool {
    let line = line.trim();
    line == "#[test]" || line.starts_with("#[tokio::test") || line.starts_with("#[gpui::test")
}

/// Names of the test functions of a source file.
fn test_functions(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim_start();
            let signature = trimmed
                .strip_prefix("async fn ")
                .or_else(|| trimmed.strip_prefix("fn "))?;
            let name = &signature[..signature.find('(')?];
            let attributed = lines[index.saturating_sub(4)..index]
                .iter()
                .any(|line| is_test_attribute(line));
            attributed.then(|| name.to_owned())
        })
        .collect()
}

fn check_test(binary: &str, test: &str) -> Result<(), String> {
    let root = binary_root(binary)?;
    let segments: Vec<&str> = test.split("::").collect();
    let (function, modules) = segments.split_last().expect("non-empty test path");
    let file = test_file(&root, modules)?;
    if test_functions(&read(&file))
        .iter()
        .any(|name| name == function)
    {
        Ok(())
    } else {
        Err(format!("no test {function} in {}", file.display()))
    }
}

/// Every test function of `cityg-core`, by file.
fn core_tests() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                for name in test_functions(&read(&path)) {
                    found.push((path.clone(), name));
                }
            }
        }
    }
    let core = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    walk(&core.join("src"), &mut found);
    walk(&core.join("tests"), &mut found);
    found
}

#[test]
fn the_manifest_points_at_real_sections_vectors_and_tests() {
    let manifest = load_json(MANIFEST);
    let vectors_path = manifest["vectors"].as_str().expect("vectors path");
    let vectors = load_json(vectors_path);
    assert_eq!(manifest["kind"], "conformance-manifest");
    assert_eq!(manifest["profile"], cityg_core::hash::PROFILE_TAG);
    assert_eq!(manifest["profile"], vectors["profile"]);
    let spec_path = manifest["spec"].as_str().expect("spec path");
    let anchors = spec_anchors(&read(&repo().join(spec_path)));
    let audit = audit_ids(&read(
        &repo().join(manifest["audit"].as_str().expect("audit path")),
    ));
    assert!(audit.contains("C-01") && audit.contains("P-8"), "{audit:?}");
    let verifier = manifest["independent_verifier"].as_str().expect("verifier");
    assert!(repo().join(verifier).is_file(), "{verifier}");

    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    for requirement in manifest["requirements"].as_array().expect("requirements") {
        let id = requirement["id"].as_str().expect("requirement id");
        let well_formed = id.split_once('.').is_some_and(|(area, number)| {
            !area.is_empty()
                && area.chars().all(|c| c.is_ascii_uppercase())
                && !number.is_empty()
                && number.chars().all(|c| c.is_ascii_digit())
        });
        if !well_formed {
            errors.push(format!("{id}: malformed requirement id"));
        }
        if !ids.insert(id.to_owned()) {
            errors.push(format!("{id}: duplicate requirement id"));
        }
        if requirement["title"].as_str().is_none_or(str::is_empty) {
            errors.push(format!("{id}: no title"));
        }
        let sections = strings(requirement, "spec", id);
        if sections.is_empty() {
            errors.push(format!("{id}: no specification section"));
        }
        for section in &sections {
            if !anchors.contains(section) {
                errors.push(format!("{id}: no anchor {section} in {spec_path}"));
            }
        }
        let findings = strings(requirement, "audit", id);
        if findings.is_empty() {
            errors.push(format!("{id}: no audit reference"));
        }
        for finding in findings {
            if !audit.contains(&finding) {
                errors.push(format!("{id}: unknown audit item {finding}"));
            }
        }
        for reference in strings(requirement, "vectors", id) {
            if let Err(err) = resolve_vector(&vectors, &reference) {
                errors.push(format!("{id}: {err}"));
            }
        }
        for script in strings(requirement, "checks", id) {
            if !repo().join(&script).is_file() {
                errors.push(format!("{id}: no script {script}"));
            }
        }
        let tests = requirement["tests"].as_array().expect("tests");
        if tests.is_empty() {
            errors.push(format!("{id}: no test"));
        }
        for test in tests {
            let binary = test["binary"].as_str().expect("test binary");
            let path = test["test"].as_str().expect("test path");
            if let Err(err) = check_test(binary, path) {
                errors.push(format!("{id}: {binary} {path}: {err}"));
            }
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn the_manifest_covers_the_specification_and_the_vectors() {
    let manifest = load_json(MANIFEST);
    let vectors = load_json(manifest["vectors"].as_str().expect("vectors path"));
    let anchors = spec_anchors(&read(
        &repo().join(manifest["spec"].as_str().expect("spec path")),
    ));
    let requirements = manifest["requirements"].as_array().expect("requirements");
    let informative: BTreeSet<String> = strings(&manifest, "informative_sections", "manifest")
        .into_iter()
        .collect();
    assert!(informative.is_subset(&anchors), "{informative:?}");

    let cited: BTreeSet<String> = requirements
        .iter()
        .flat_map(|requirement| strings(requirement, "spec", "requirement"))
        .collect();
    let uncovered: Vec<&String> = anchors
        .iter()
        .filter(|anchor| !cited.contains(*anchor) && !informative.contains(*anchor))
        .collect();
    assert!(
        uncovered.is_empty(),
        "sections without requirement: {uncovered:?}"
    );
    let both: Vec<&String> = informative.intersection(&cited).collect();
    assert!(both.is_empty(), "informative sections cited: {both:?}");

    let references: Vec<String> = requirements
        .iter()
        .flat_map(|requirement| strings(requirement, "vectors", "requirement"))
        .collect();
    let sections: Vec<&String> = vectors
        .as_object()
        .expect("vector object")
        .iter()
        .filter(|(_, value)| value.is_object() || value.is_array())
        .map(|(name, _)| name)
        .collect();
    assert!(sections.len() >= 9, "{sections:?}");
    for section in sections {
        let prefix = format!("/{section}");
        assert!(
            references.iter().any(|reference| reference == &prefix
                || reference.starts_with(&format!("{prefix}/"))
                || reference.starts_with(&format!("{prefix}#"))),
            "vector section {section} is not cited"
        );
    }
    for object in vectors["signed_objects"]
        .as_array()
        .expect("signed objects")
    {
        let reference = format!("/signed_objects#{}", object["id"].as_str().expect("id"));
        assert!(
            references.contains(&reference),
            "signed object {reference} is not cited"
        );
    }
}

#[test]
fn every_core_test_is_mapped_to_a_requirement() {
    let manifest = load_json(MANIFEST);
    let mapped: BTreeSet<String> = manifest["requirements"]
        .as_array()
        .expect("requirements")
        .iter()
        .flat_map(|requirement| requirement["tests"].as_array().expect("tests"))
        .filter(|test| {
            test["binary"]
                .as_str()
                .is_some_and(|binary| binary.split("::").next() == Some("cityg-core"))
        })
        .map(|test| {
            let path = test["test"].as_str().expect("test path");
            path.rsplit("::").next().expect("function").to_owned()
        })
        .collect();
    let this_file = file!().rsplit('/').next().expect("file name");
    let unmapped: Vec<String> = core_tests()
        .into_iter()
        .filter(|(file, name)| {
            // The checks of this file are about the manifest itself.
            !file.ends_with(this_file) && !mapped.contains(name)
        })
        .map(|(file, name)| format!("{}: {name}", file.display()))
        .collect();
    assert!(
        unmapped.is_empty(),
        "unmapped tests:\n{}",
        unmapped.join("\n")
    );
}

#[test]
fn the_checker_resolves_modules_and_rejects_missing_tests() {
    assert!(check_test("cityg-core", "cbor::tests::encodes_rfc8949_examples").is_ok());
    assert!(check_test("cityg-core", "session::tests::members_join_talk_and_leave").is_ok());
    assert!(check_test("cityg-core::vectors", "vectors_are_reproducible").is_ok());
    assert!(check_test("cityg-core", "cbor::tests::no_such_test").is_err());
    assert!(check_test("cityg-core", "no_such_module::tests::x").is_err());
    assert!(check_test("cityg-core::no_such_binary", "x").is_err());
    assert!(
        check_test("cityg-core", "cbor::tests::uint").is_err(),
        "helpers are not tests"
    );
    let vectors = load_json("kat/v0.2/vectors.json");
    assert!(resolve_vector(&vectors, "/signed_objects#invite").is_ok());
    assert!(resolve_vector(&vectors, "/signed_objects#nothing").is_err());
    assert!(resolve_vector(&vectors, "/nothing").is_err());
    assert_eq!(
        declares_module("pub(crate) mod tests {", "tests"),
        Some(true)
    );
    assert_eq!(declares_module("mod tests;", "tests"), Some(false));
    assert_eq!(declares_module("mod testsuite;", "tests"), None);
}
