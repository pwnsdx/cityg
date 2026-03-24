use super::*;

pub(super) async fn perform_fetch_members(params: MembersParams) -> Result<MembersPage> {
    let client = new_api_client(&params.server_url);
    let (raw_members, root, total_count, next_offset) = match &params.mode {
        MembersMode::Full => {
            // Always resolve the first page against latest server root to avoid
            // sticking to an old-but-still-valid parent_root after missed events.
            let response = if params.offset == 0 {
                client
                    .members_with_range(&params.gid, None, Some(params.offset), Some(params.limit))
                    .await?
            } else {
                match client
                    .members_with_range(
                        &params.gid,
                        Some(&params.parent_root),
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                        info!(
                            "members root {} not found for gid {}; retrying with latest root",
                            hex_encode(params.parent_root),
                            hex_encode(params.gid)
                        );
                        client
                            .members_with_range(
                                &params.gid,
                                None,
                                Some(params.offset),
                                Some(params.limit),
                            )
                            .await?
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            (
                response.members,
                response.root,
                response.total_count,
                response.next_offset,
            )
        }
        MembersMode::Search { query } => {
            // Same latest-root bootstrap for search mode first page.
            let response = if params.offset == 0 {
                client
                    .search_members(
                        &params.gid,
                        query,
                        None,
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await?
            } else {
                match client
                    .search_members(
                        &params.gid,
                        query,
                        Some(&params.parent_root),
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                        info!(
                            "search root {} not found for gid {}; retrying with latest root",
                            hex_encode(params.parent_root),
                            hex_encode(params.gid)
                        );
                        client
                            .search_members(
                                &params.gid,
                                query,
                                None,
                                Some(params.offset),
                                Some(params.limit),
                            )
                            .await?
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            (
                response.members,
                response.root,
                response.total_count,
                response.next_offset,
            )
        }
    };
    let root: [u8; 32] = root
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("members root must be 32 bytes"))?;
    if params.offset == 0 {
        verify_members_root_consistency(&client, &params.gid, &root)
            .await
            .context("failed to verify member roster root")?;
    }
    let mut members = Vec::with_capacity(raw_members.len());
    for entry in raw_members {
        let leaf_id = parse_member_leaf_id(entry.leaf_id.as_slice())?;
        let alias = entry.alias.filter(|alias| !alias.trim().is_empty());
        let pop_public_key = entry.pop_public_key.filter(|pk| !pk.is_empty());
        members.push(MemberEntry {
            leaf_id,
            alias,
            pop_public_key,
            join_timestamp_ms: entry.join_date,
            last_seen_timestamp_ms: entry.last_seen,
        });
    }
    Ok(MembersPage {
        members,
        root,
        total_count,
        next_offset,
    })
}
