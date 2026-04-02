use std::collections::BTreeMap;

use anyhow::Result;
use ciborium::value::Value;
use msphf_orchestrator::{AnchorInstanceParts, ForwardSecrecyState, OrchestrationParams};

use crate::{CityGClient, ClientEpochBundle};

pub struct JoinEpochBundleInputs<'a> {
    pub header: BTreeMap<u64, Value>,
    pub parts: AnchorInstanceParts<'a>,
    pub params: OrchestrationParams<'a>,
    pub fs_state: &'a mut ForwardSecrecyState,
    pub witness_bytes: Option<&'a [u8]>,
    pub disable_autonomic_evolve: bool,
}

pub fn build_join_epoch_bundle(inputs: JoinEpochBundleInputs<'_>) -> Result<ClientEpochBundle> {
    let JoinEpochBundleInputs {
        header,
        parts,
        params,
        fs_state,
        witness_bytes,
        disable_autonomic_evolve,
    } = inputs;

    if disable_autonomic_evolve {
        Ok(CityGClient::generate_epoch_without_evolve(
            header,
            parts,
            params,
            fs_state,
            witness_bytes,
        )?)
    } else {
        Ok(CityGClient::generate_epoch(
            header,
            parts,
            params,
            fs_state,
            witness_bytes,
        )?)
    }
}
