pub mod agent_error;
pub mod replica_api;
pub mod response;
pub mod response_authentication;
pub mod signed;

use crate::{
    agent::replica_api::{CallRequestContent, Certificate, Delegation, ReadStateContent},
    agent::response_authentication::{extract_der, lookup_value},
    bls::bls12381::bls,
    export::Principal,
    hash_tree::Label,
    request_id::{to_request_id, RequestId},
};
pub use agent_error::AgentError;
pub use response::{Replied, RequestStatusResponse};

use std::time::Duration;

const IC_REQUEST_DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";
const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

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

/// Verify a certificate, checking delegation if present.
/// Only passes if the certificate also has authority over the canister.
pub fn verify(
    cert: &Certificate,
    effective_canister_id: Principal,
    disable_range_check: bool,
) -> Result<(), AgentError> {
    let sig = &cert.signature;

    let root_hash = cert.tree.digest();
    let mut msg = vec![];
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);

    let der_key = check_delegation(&cert.delegation, effective_canister_id, disable_range_check)?;
    let key = extract_der(der_key)?;
    let result = bls::core_verify(sig, &*msg, &*key);
    if result != bls::BLS_OK {
        Err(AgentError::CertificateVerificationFailed())
    } else {
        Ok(())
    }
}

fn check_delegation(
    delegation: &Option<Delegation>,
    effective_canister_id: Principal,
    disable_range_check: bool,
) -> Result<Vec<u8>, AgentError> {
    match delegation {
        None => Ok(IC_ROOT_KEY.to_vec()),
        Some(delegation) => {
            let cert: Certificate = serde_cbor::from_slice(&delegation.certificate)
                .map_err(AgentError::InvalidCborData)?;
            verify(&cert, effective_canister_id, disable_range_check)?;
            let canister_range_lookup = [
                "subnet".into(),
                delegation.subnet_id.clone().into(),
                "canister_ranges".into(),
            ];
            let canister_range = lookup_value(&cert, canister_range_lookup)?;
            let ranges: Vec<(Principal, Principal)> =
                serde_cbor::from_slice(canister_range).map_err(AgentError::InvalidCborData)?;
            if !disable_range_check
                && !principal_is_within_ranges(&effective_canister_id, &ranges[..])
            {
                // the certificate is not authorized to answer calls for this canister
                return Err(AgentError::CertificateNotAuthorized());
            }

            let public_key_path = [
                "subnet".into(),
                delegation.subnet_id.clone().into(),
                "public_key".into(),
            ];
            lookup_value(&cert, public_key_path).map(|pk| pk.to_vec())
        }
    }
}

// Checks if a principal is contained within a list of principal ranges
// A range is a tuple: (low: Principal, high: Principal), as described here: https://docs.dfinity.systems/spec/public/#state-tree-subnet
fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|r| principal >= &r.0 && principal <= &r.1)
}
