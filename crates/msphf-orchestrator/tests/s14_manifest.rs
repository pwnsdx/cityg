use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct S14Manifest {
    profile_version: String,
    requirements: Vec<S14Requirement>,
}

#[derive(Debug, Deserialize)]
struct S14Requirement {
    id: String,
    coverage: Vec<S14Coverage>,
}

#[derive(Debug, Deserialize)]
struct S14Coverage {
    #[serde(rename = "crate")]
    crate_name: String,
    test: String,
    expectation: String,
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../kat/kat-s14-conformance-manifest-v0.1.2.json")
}

fn freeze_blockers_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../kat/kat-freeze-blockers-manifest-v0.1.2-errata.json")
}

fn crate_root(crate_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates")
        .join(crate_name)
}

fn rust_source_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn test_symbol_exists(
    crate_name: &str,
    test_path: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let symbol = test_path
        .rsplit("::")
        .next()
        .ok_or("test path missing symbol name")?;
    let fn_marker = format!("fn {symbol}");
    let async_fn_marker = format!("async fn {symbol}");
    for file in rust_source_files(&crate_root(crate_name))? {
        let contents = fs::read_to_string(file)?;
        if contents.contains(&fn_marker) || contents.contains(&async_fn_marker) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_manifest(
    manifest: S14Manifest,
    expected: BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(manifest.profile_version, "v0.1.2");
    assert_eq!(manifest.requirements.len(), expected.len());

    let mut ids = BTreeSet::new();
    for requirement in manifest.requirements {
        assert!(
            ids.insert(requirement.id.clone()),
            "duplicate requirement id"
        );
        assert!(
            !requirement.coverage.is_empty(),
            "requirement {} has no coverage entries",
            requirement.id
        );
        for entry in requirement.coverage {
            assert!(
                !entry.crate_name.trim().is_empty(),
                "crate name must be present"
            );
            assert!(!entry.test.trim().is_empty(), "test name must be present");
            assert!(
                !entry.expectation.trim().is_empty(),
                "expectation must be present"
            );
            assert!(
                test_symbol_exists(&entry.crate_name, &entry.test)?,
                "coverage entry {}::{} does not reference an existing test function",
                entry.crate_name,
                entry.test
            );
        }
    }

    assert_eq!(ids, expected);
    Ok(())
}

#[test]
fn s14_manifest_is_well_formed_and_complete() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(manifest_path())?;
    let manifest: S14Manifest = serde_json::from_slice(&bytes)?;

    let expected = BTreeSet::from([
        "S14.1".to_string(),
        "S14.2".to_string(),
        "S14.3".to_string(),
        "S14.4".to_string(),
        "S14.5".to_string(),
        "S14.6".to_string(),
    ]);
    validate_manifest(manifest, expected)
}

#[test]
fn freeze_blockers_manifest_is_well_formed_and_complete() -> Result<(), Box<dyn std::error::Error>>
{
    let bytes = fs::read(freeze_blockers_manifest_path())?;
    let manifest: S14Manifest = serde_json::from_slice(&bytes)?;

    let expected = BTreeSet::from([
        "ERRATA.1".to_string(),
        "ERRATA.2".to_string(),
        "ERRATA.3".to_string(),
        "ERRATA.4".to_string(),
    ]);
    validate_manifest(manifest, expected)
}
