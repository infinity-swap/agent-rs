pub mod agent_error;
pub mod replica_api;
pub mod response;
pub mod signed;

use crate::{
    agent::replica_api::{CallRequestContent, ReadStateContent},
    export::Principal,
    hash_tree::Label,
    request_id::{to_request_id, RequestId},
};
pub use agent_error::AgentError;
pub use response::{Replied, RequestStatusResponse};

use std::time::Duration;

const IC_REQUEST_DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";

#[derive(Default, Clone, Debug)]
pub struct Signature {
    /// This is the DER-encoded public key.
    pub public_key: Option<Vec<u8>>,
    /// The signature bytes.
    pub signature: Option<Vec<u8>>,
}

pub fn get_expiry_date(ingress_expiry_duration: Duration) -> u64 {
    // TODO(hansl): evaluate if we need this on the agent side (my hunch is we don't).
    let permitted_drift = Duration::from_secs(60);
    (ingress_expiry_duration
        .as_nanos()
        .saturating_add(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time wrapped around.")
                .as_nanos(),
        )
        .saturating_sub(permitted_drift.as_nanos())) as u64
}

pub fn update_content(
    sender: Principal,
    canister_id: &Principal,
    method_name: &str,
    arg: &[u8],
    nonce: Vec<u8>,
    ingress_expiry: u64,
) -> Result<CallRequestContent, AgentError> {
    Ok(CallRequestContent::CallRequest {
        canister_id: *canister_id,
        method_name: method_name.into(),
        arg: arg.to_vec(),
        nonce: Some(nonce),
        sender,
        ingress_expiry,
    })
}

pub fn construct_message(request_id: &RequestId) -> Vec<u8> {
    let mut buf = vec![];
    buf.extend_from_slice(IC_REQUEST_DOMAIN_SEPARATOR);
    buf.extend_from_slice(request_id.as_slice());
    buf
}

/// Sign a update call. This will return a [`signed::SignedUpdate`]
/// which contains all fields of the update and the signed update in CBOR encoding
pub fn sign(
    sender: Principal,
    canister_id: &Principal,
    effective_canister_id: Principal,
    method_name: &str,
    arg: &[u8],
    nonce: Vec<u8>,
    ingress_expiry_datetime: u64,
    signed_update: Vec<u8>,
) -> Result<signed::SignedUpdate, AgentError> {
    let request = update_content(
        sender,
        &canister_id,
        &method_name,
        &arg,
        nonce,
        ingress_expiry_datetime,
    )?;
    // let signed_update = sign_request(&request, self.agent.identity.clone())?;
    let request_id = to_request_id(&request)?;
    match request {
        CallRequestContent::CallRequest {
            nonce,
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
        } => Ok(signed::SignedUpdate {
            nonce,
            ingress_expiry,
            sender,
            canister_id,
            method_name,
            arg,
            effective_canister_id,
            signed_update,
            request_id,
        }),
    }
}

pub fn read_state_content(
    sender: Principal,
    paths: Vec<Vec<Label>>,
    ingress_expiry: u64,
) -> Result<ReadStateContent, AgentError> {
    Ok(ReadStateContent::ReadStateRequest {
        sender,
        paths,
        ingress_expiry,
    })
}
