use std::{collections::BTreeSet, fs, path::PathBuf};

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

#[test]
fn s14_manifest_is_well_formed_and_complete() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(manifest_path())?;
    let manifest: S14Manifest = serde_json::from_slice(&bytes)?;

    assert_eq!(manifest.profile_version, "v0.1.2");
    assert_eq!(manifest.requirements.len(), 6, "expect S14.1..S14.6");

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
        }
    }

    let expected = BTreeSet::from([
        "S14.1".to_string(),
        "S14.2".to_string(),
        "S14.3".to_string(),
        "S14.4".to_string(),
        "S14.5".to_string(),
        "S14.6".to_string(),
    ]);
    assert_eq!(ids, expected);
    Ok(())
}

#[test]
fn freeze_blockers_manifest_is_well_formed_and_complete() -> Result<(), Box<dyn std::error::Error>>
{
    let bytes = fs::read(freeze_blockers_manifest_path())?;
    let manifest: S14Manifest = serde_json::from_slice(&bytes)?;

    assert_eq!(manifest.profile_version, "v0.1.2");
    assert_eq!(manifest.requirements.len(), 4, "expect ERRATA.1..ERRATA.4");

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
        }
    }

    let expected = BTreeSet::from([
        "ERRATA.1".to_string(),
        "ERRATA.2".to_string(),
        "ERRATA.3".to_string(),
        "ERRATA.4".to_string(),
    ]);
    assert_eq!(ids, expected);
    Ok(())
}
