// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use openshell_core::token_grant_failure::WORKLOAD_IDENTITY_CALL_TIMEOUT;
use spiffe::{WorkloadApiClient, WorkloadApiError, X509Context};
use tonic::{Status, transport::Identity};
use zeroize::Zeroizing;

pub(super) async fn fetch_x509_context(socket: &str) -> Result<X509Context, WorkloadApiError> {
    WorkloadApiClient::connect_to(format!("unix:{socket}"))
        .await?
        .fetch_x509_context()
        .await
}

/// Read the dedicated supervisor X.509-SVID for one admission connection.
/// Its private key stays in memory and its bundle does not set gateway trust.
pub async fn supervisor_tls_identity(socket: &Path) -> Result<Identity, Status> {
    openshell_core::driver_utils::validate_provider_spiffe_unix_socket(socket)
        .map_err(Status::failed_precondition)?;
    let socket = socket.to_str().ok_or_else(|| {
        Status::failed_precondition("bootstrap SPIFFE Workload API socket must be valid UTF-8")
    })?;
    let context = tokio::time::timeout(WORKLOAD_IDENTITY_CALL_TIMEOUT, fetch_x509_context(socket))
        .await
        .map_err(|_| Status::deadline_exceeded("bootstrap SPIFFE Workload API timed out"))?
        .map_err(|error| match error {
            WorkloadApiError::NoIdentityIssued
            | WorkloadApiError::EmptyResponse
            | WorkloadApiError::Transport(_) => {
                Status::unavailable("bootstrap SPIFFE identity is unavailable")
            }
            _ => Status::permission_denied("bootstrap SPIFFE identity was rejected"),
        })?;
    let [svid] = context.svids() else {
        return Err(Status::permission_denied(
            "bootstrap SPIFFE Workload API must supply one supervisor identity",
        ));
    };
    let mut chain = String::new();
    for cert in svid.cert_chain() {
        chain.push_str(&pem::encode(&pem::Pem::new("CERTIFICATE", cert.as_ref())));
    }
    let key = pem::Pem::new("PRIVATE KEY", svid.private_key().as_ref());
    let encoded = Zeroizing::new(pem::encode(&key));
    drop(Zeroizing::new(key.into_contents()));
    Ok(Identity::from_pem(chain, encoded.as_bytes()))
}
