use cityg_api_schema::pb::{
    MembersRequest, MembersResponse, SearchMembersRequest, SearchMembersResponse,
};

use crate::{CitygApiClient, Error};

impl CitygApiClient {
    pub async fn members(
        &self,
        gid: &[u8],
        parent_root: Option<&[u8; 32]>,
    ) -> Result<MembersResponse, Error> {
        self.members_with_range(gid, parent_root, None, None).await
    }

    pub async fn members_with_range(
        &self,
        gid: &[u8],
        parent_root: Option<&[u8; 32]>,
        offset: Option<u64>,
        limit: Option<u32>,
    ) -> Result<MembersResponse, Error> {
        let request = MembersRequest {
            gid: gid.to_vec(),
            parent_root: parent_root.map(|root| root.to_vec()).unwrap_or_default(),
            offset,
            limit,
        };
        self.post_proto("/v1/members", request).await
    }

    pub async fn search_members(
        &self,
        gid: &[u8],
        query: &str,
        parent_root: Option<&[u8; 32]>,
        offset: Option<u64>,
        limit: Option<u32>,
    ) -> Result<SearchMembersResponse, Error> {
        let request = SearchMembersRequest {
            gid: gid.to_vec(),
            query: query.to_string(),
            parent_root: parent_root.map(|root| root.to_vec()).unwrap_or_default(),
            offset,
            limit,
        };
        self.post_proto("/v1/members/search", request).await
    }
}
