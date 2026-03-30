use super::*;
use crate::demo;

#[test]
fn update_window_limits_updates_context_and_receiver_ttl() {
    let mut server = demo::demo_server();
    server.update_window_limits(Some(3), Some(Duration::from_secs(9)));
    let (h_max, ttl) = server.window_limits();
    assert_eq!(h_max, 3);
    assert_eq!(ttl, Duration::from_secs(9));
}

#[test]
fn refresh_pivot_requires_pivot_weid_header() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let pivot_weid = server
        .context_mut()
        .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
        .into_iter()
        .next()
        .ok_or(CityGError::InvalidInput("pivot parity missing"))?
        .we_epoch_id;
    let mut invalid = bundle.clone();
    invalid.header_map.insert(
        hdr::HDR_ROLLUP_PIVOT_WEID,
        Value::Bytes(pivot_weid.to_vec()),
    );
    invalid
        .header_map
        .remove(&msphf_orchestrator::hdr::HDR_ROLLUP_PIVOT_WEID);
    let err = server
        .refresh_pivot(&invalid)
        .expect_err("missing pivot_weid header should fail");
    assert!(matches!(err, CityGError::InvalidInput("pivot_weid")));
    Ok(())
}

#[test]
fn refresh_pivot_rejects_mutated_proof_material() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let mut tampered = bundle.clone();
    let pivot_weid = server
        .context_mut()
        .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
        .into_iter()
        .next()
        .ok_or(CityGError::InvalidInput("pivot parity missing"))?
        .we_epoch_id;
    tampered.header_map.insert(
        hdr::HDR_ROLLUP_PIVOT_WEID,
        Value::Bytes(pivot_weid.to_vec()),
    );
    let proof_field = tampered
        .header_map
        .get_mut(&hdr::HDR_VRF_PROOF)
        .ok_or(CityGError::InvalidInput("vrf proof missing from bundle"))?;
    if let Value::Bytes(bytes) = proof_field {
        if let Some(first) = bytes.first_mut() {
            *first ^= 0x01;
        }
    } else {
        return Err(CityGError::InvalidInput("vrf proof has invalid type"));
    }

    let err = server
        .refresh_pivot(&tampered)
        .err()
        .ok_or(CityGError::InvalidInput(
            "tampered refresh bundle must fail",
        ))?;
    assert!(matches!(
        err,
        CityGError::InvalidInput("refresh payload diverges from stored parity")
    ));
    Ok(())
}

#[test]
fn refresh_pivot_accepts_matching_parity_payload() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let pivot_weid = server
        .context_mut()
        .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
        .into_iter()
        .next()
        .ok_or(CityGError::InvalidInput("pivot parity missing"))?
        .we_epoch_id;
    let mut refresh = bundle.clone();
    refresh.header_map.insert(
        hdr::HDR_ROLLUP_PIVOT_WEID,
        Value::Bytes(pivot_weid.to_vec()),
    );

    server.refresh_pivot(&refresh)?;
    let still_present = server
        .context_mut()
        .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
        .into_iter()
        .any(|parity| parity.we_epoch_id == pivot_weid);
    assert!(
        still_present,
        "refresh should preserve pivot parity entry in store"
    );
    Ok(())
}

#[test]
fn refresh_pivot_rejects_unknown_pivot_weid() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let mut refresh = bundle.clone();
    refresh.header_map.insert(
        hdr::HDR_ROLLUP_PIVOT_WEID,
        Value::Bytes([0xEE; 32].to_vec()),
    );
    let err = server
        .refresh_pivot(&refresh)
        .expect_err("unknown pivot parity must fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput("pivot parity missing for refresh")
    ));
    Ok(())
}
