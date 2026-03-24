use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ClientStateManifest {
    profile_version: String,
    requirements: Vec<ClientStateRequirement>,
}

#[derive(Debug, Deserialize)]
struct ClientStateRequirement {
    id: String,
    coverage: Vec<ClientStateCoverage>,
}

#[derive(Debug, Deserialize)]
struct ClientStateCoverage {
    #[serde(rename = "crate")]
    crate_name: String,
    test: String,
    expectation: String,
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../kat/kat-client-state-manifest-v0.1.4.json")
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

#[test]
fn client_state_manifest_is_well_formed_and_complete() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(manifest_path())?;
    let manifest: ClientStateManifest = serde_json::from_slice(&bytes)?;

    assert_eq!(manifest.profile_version, "v0.1.4");

    let expected = BTreeSet::from([
        "CLIENT_STATE.1".to_string(),
        "CLIENT_STATE.2".to_string(),
        "CLIENT_STATE.3".to_string(),
        "CLIENT_STATE.4".to_string(),
        "CLIENT_STATE.5".to_string(),
        "CLIENT_STATE.6".to_string(),
        "CLIENT_STATE.7".to_string(),
        "CLIENT_STATE.8".to_string(),
        "CLIENT_STATE.9".to_string(),
    ]);

    assert_eq!(manifest.requirements.len(), expected.len());
    let mut seen = BTreeSet::new();
    for requirement in manifest.requirements {
        assert!(
            seen.insert(requirement.id.clone()),
            "duplicate client-state requirement id"
        );
        assert!(
            !requirement.coverage.is_empty(),
            "client-state requirement {} has no coverage entries",
            requirement.id
        );
        for coverage in requirement.coverage {
            assert!(
                !coverage.crate_name.trim().is_empty(),
                "coverage crate name must be present"
            );
            assert!(
                !coverage.test.trim().is_empty(),
                "coverage test must be present"
            );
            assert!(
                !coverage.expectation.trim().is_empty(),
                "coverage expectation must be present"
            );
            assert!(
                test_symbol_exists(&coverage.crate_name, &coverage.test)?,
                "coverage entry {}::{} does not reference an existing test function",
                coverage.crate_name,
                coverage.test
            );
        }
    }

    assert_eq!(seen, expected);
    Ok(())
}
