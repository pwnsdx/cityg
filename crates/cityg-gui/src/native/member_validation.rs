use super::*;

pub(super) const MEMBERS_ROOT_VERIFY_PAGE_LIMIT: u32 = 2_000;

pub(super) fn parse_member_leaf_id(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("member leaf id must be 32 bytes"))
}

pub(super) fn validate_members_root_from_leaves(
    root: [u8; 32],
    mut leaves: Vec<[u8; 32]>,
    total_count: u64,
) -> Result<()> {
    if leaves.len() as u64 != total_count {
        return Err(anyhow!(
            "members root validation failed: expected {total_count} leaves, received {}",
            leaves.len()
        ));
    }
    leaves.sort_unstable();
    let computed = canonical_set_root(&leaves)
        .map_err(|err| anyhow!("members root validation failed: unable to compute root: {err}"))?;
    if computed != root {
        return Err(anyhow!(
            "members root validation failed: computed {} but server reported {}",
            hex_encode(computed),
            hex_encode(root)
        ));
    }
    Ok(())
}

pub(super) async fn verify_members_root_consistency(
    client: &CitygApiClient,
    gid: &[u8; 32],
    root: &[u8; 32],
) -> Result<()> {
    let mut offset = 0u64;
    let mut expected_total: Option<u64> = None;
    let mut leaves: Vec<[u8; 32]> = Vec::new();

    loop {
        let response = client
            .members_with_range(
                gid,
                Some(root),
                Some(offset),
                Some(MEMBERS_ROOT_VERIFY_PAGE_LIMIT),
            )
            .await?;

        let response_root: [u8; 32] = response
            .root
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("members root must be 32 bytes"))?;
        if response_root != *root {
            return Err(anyhow!(
                "members root validation failed: page root {} did not match expected {}",
                hex_encode(response_root),
                hex_encode(*root)
            ));
        }

        match expected_total {
            Some(total) if total != response.total_count => {
                return Err(anyhow!(
                    "members root validation failed: inconsistent total_count ({total} vs {})",
                    response.total_count
                ));
            }
            None => expected_total = Some(response.total_count),
            _ => {}
        }

        for entry in response.members {
            leaves.push(parse_member_leaf_id(entry.leaf_id.as_slice())?);
        }

        if response.next_offset >= response.total_count {
            break;
        }
        if response.next_offset <= offset {
            return Err(anyhow!(
                "members root validation failed: non-increasing pagination offset {} -> {}",
                offset,
                response.next_offset
            ));
        }
        offset = response.next_offset;
    }

    validate_members_root_from_leaves(*root, leaves, expected_total.unwrap_or(0))
}
