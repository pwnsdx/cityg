use cityg_api_schema::pb::{
    PendingRemoveProposalsRequest, PendingRemoveProposalsResponse, SubmitRemoveProposalRequest,
    SubmitRemoveProposalResponse,
};
use cityg_client::remove_proposal::SignedRemoveProposal;

use crate::{CitygApiClient, Error};

impl CitygApiClient {
    /// Submits a signed removal proposal (a member's own leave request, or a
    /// room admin's expulsion request). Another member commits it with a
    /// LEAVE merge ticket; the server only stores it.
    pub async fn submit_remove_proposal(
        &self,
        room_id: &str,
        proposal: &SignedRemoveProposal,
    ) -> Result<SubmitRemoveProposalResponse, Error> {
        let request = SubmitRemoveProposalRequest {
            room_id: room_id.to_string(),
            signed_proposal: proposal
                .to_cbor()
                .map_err(|err| Error::Parse(err.to_string()))?,
        };
        self.post_proto("/v1/rooms/remove_proposal", request).await
    }

    /// Fetches the pending removal proposals of a room. Every proposal is
    /// decoded and its signature verified locally; proposals for another room
    /// are rejected, so callers never act on a server-forged removal.
    pub async fn pending_remove_proposals(
        &self,
        room_id: &str,
        gid: &[u8; 32],
    ) -> Result<Vec<SignedRemoveProposal>, Error> {
        let request = PendingRemoveProposalsRequest {
            room_id: room_id.to_string(),
        };
        let response: PendingRemoveProposalsResponse = self
            .post_proto("/v1/rooms/pending_remove_proposals", request)
            .await?;
        response
            .signed_proposals
            .iter()
            .map(|encoded| {
                let proposal = SignedRemoveProposal::from_cbor(encoded)
                    .map_err(|err| Error::Parse(err.to_string()))?;
                proposal
                    .verify_signature()
                    .map_err(|err| Error::Parse(err.to_string()))?;
                if proposal.proposal.gid != *gid {
                    return Err(Error::Parse(
                        "pending removal proposal targets another room".to_string(),
                    ));
                }
                Ok(proposal)
            })
            .collect()
    }
}
