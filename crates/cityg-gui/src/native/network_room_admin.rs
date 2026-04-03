use super::*;

pub(super) async fn perform_fetch_room_admins(
    params: RoomAdminQueryParams,
) -> Result<Vec<Vec<u8>>> {
    let client = new_api_client(&params.server_url);
    let identity = cityg_api_client::RoomAdminIdentity {
        pop_public_key: params.pop_public_key.clone(),
        pop_secret_key: params.pop_secret_key.clone(),
    };
    let admin_proof = identity
        .build_listing_proof(&params.room_id)
        .context("build room admin listing proof")?;
    let response = client
        .list_room_admins(&params.room_id, admin_proof)
        .await
        .context("list room admins")?;
    Ok(response.admin_pop_public_keys)
}

pub(super) async fn perform_room_admin_mutation(
    params: RoomAdminMutationParams,
) -> Result<RoomAdminMutationOutcome> {
    let client = new_api_client(&params.query.server_url);
    let identity = cityg_api_client::RoomAdminIdentity {
        pop_public_key: params.query.pop_public_key.clone(),
        pop_secret_key: params.query.pop_secret_key.clone(),
    };
    let admin_proof = identity
        .build_target_proof(
            params.kind.operation(),
            &params.query.room_id,
            &params.target_pop_public_key,
        )
        .with_context(|| {
            format!(
                "build {} room admin proof",
                match params.kind {
                    RoomAdminMutationKind::Grant => "grant",
                    RoomAdminMutationKind::Revoke => "revoke",
                }
            )
        })?;
    let response = match params.kind {
        RoomAdminMutationKind::Grant => client
            .grant_room_admin(
                &params.query.room_id,
                &params.target_pop_public_key,
                admin_proof,
            )
            .await
            .context("grant room admin")?,
        RoomAdminMutationKind::Revoke => client
            .revoke_room_admin(
                &params.query.room_id,
                &params.target_pop_public_key,
                admin_proof,
            )
            .await
            .context("revoke room admin")?,
    };
    Ok(RoomAdminMutationOutcome {
        status: response.status,
        admin_count: response.admin_count,
    })
}
