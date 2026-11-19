// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use openshell_core::bootstrap_authz::{
    AttestationContext, Denial, DeviceAttestation, DeviceAttestationAdapter,
    SandboxAuthorizationAdapter, SandboxIntent, Stage,
};
use openshell_core::config::BootstrapPostureAuthorityConfig;
use openshell_core::proto::{WorkspaceMember, WorkspaceRole};
use serde::{Deserialize, Serialize};

use crate::auth::workspace_authz::{MinWorkspaceRole, role_satisfies};
use crate::persistence::Store;

const MAX_RESPONSE_BYTES: usize = 65_536;

pub struct PostureAuthority {
    client: reqwest::Client,
    endpoint: url::Url,
}

impl PostureAuthority {
    pub fn new(config: &BootstrapPostureAuthorityConfig) -> Result<Self, String> {
        let endpoint = url::Url::parse(&config.endpoint)
            .ok()
            .filter(|url| {
                url.scheme() == "https"
                    && url.has_host()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
            .ok_or("invalid bootstrap posture authority HTTPS endpoint")?;
        let roots = reqwest::Certificate::from_pem_bundle(&read_pem(&config.ca_bundle)?)
            .map_err(|_| "invalid bootstrap posture authority CA bundle")?;
        if roots.is_empty() {
            return Err("bootstrap posture authority CA bundle is empty".into());
        }
        let identity = reqwest::Identity::from_pem(&read_pem(&config.client_identity_pem)?)
            .map_err(|_| "invalid bootstrap posture authority client identity")?;
        openshell_crypto::tls::ensure_default_provider();
        let client = roots
            .into_iter()
            .fold(
                reqwest::Client::builder()
                    .https_only(true)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .tls_built_in_root_certs(false)
                    .identity(identity)
                    .timeout(Duration::from_secs(10)),
                reqwest::ClientBuilder::add_root_certificate,
            )
            .build()
            .map_err(|_| "cannot configure bootstrap posture authority mTLS")?;
        Ok(Self { client, endpoint })
    }
}

fn read_pem(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    const MAX_PEM: u64 = 1_048_576;
    if !path.is_absolute() || !path.is_file() {
        return Err("bootstrap posture authority PEM must be an absolute file path".into());
    }
    let mut pem = zeroize::Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_PEM + 1).read_to_end(&mut pem))
        .map_err(|_| "cannot read bootstrap posture authority PEM")?;
    if pem.is_empty() || pem.len() as u64 > MAX_PEM {
        return Err("bootstrap posture authority PEM size is invalid".into());
    }
    Ok(pem)
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    stage: Stage,
    challenge: &'a str,
    intent: &'a SandboxIntent,
    runtime_identity: Option<&'a str>,
    expected_device_id: Option<&'a str>,
    request_evidence: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedEvidence {
    owner: String,
    device_id: String,
    device_revision: String,
    challenge: String,
    issued_at: i64,
    expires_at: i64,
    compliant: bool,
    host_id: Option<String>,
    runtime_identity: Option<String>,
    selectors: BTreeSet<String>,
    workload_key_pem: Option<String>,
}

#[async_trait]
impl DeviceAttestationAdapter for PostureAuthority {
    async fn attest(&self, context: &AttestationContext) -> Result<DeviceAttestation, Denial> {
        let request = VerifyRequest {
            stage: context.stage,
            challenge: &context.challenge,
            intent: &context.intent,
            runtime_identity: context.runtime_identity.as_deref(),
            expected_device_id: context.expected_device_id.as_deref(),
            // The workload proof is consumed at the gateway. Sending it to
            // another service would expose an unconsumed request proof.
            request_evidence: if context.stage == Stage::Bootstrap {
                context.request_evidence.as_deref()
            } else {
                None
            },
        };
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .json(&request)
            .send()
            .await
            .map_err(|_| Denial::Unavailable)?;
        match response.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::FORBIDDEN => return Err(Denial::PolicyDenied),
            _ => return Err(Denial::Unavailable),
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Denial::Unavailable)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(Denial::InvalidDecision);
            }
            body.extend_from_slice(&chunk);
        }
        let evidence: VerifiedEvidence =
            serde_json::from_slice(&body).map_err(|_| Denial::InvalidDecision)?;
        Ok(DeviceAttestation {
            owner: evidence.owner,
            device_id: evidence.device_id,
            device_revision: evidence.device_revision,
            challenge: evidence.challenge,
            issued_at: evidence.issued_at,
            expires_at: evidence.expires_at,
            compliant: evidence.compliant,
            host_id: evidence.host_id,
            runtime_identity: evidence.runtime_identity,
            selectors: evidence.selectors,
            workload_key_pem: evidence.workload_key_pem.map(String::into_bytes),
        })
    }
}

/// Owner-only pilot. Recheck explicit workspace membership on every decision.
pub struct WorkspaceOwnerAuthorization(pub Arc<Store>);

#[async_trait]
impl SandboxAuthorizationAdapter for WorkspaceOwnerAuthorization {
    async fn verify(&self, intent: &SandboxIntent, _: i64) -> Result<(), Denial> {
        crate::grpc::workspace::resolve_workspace(&self.0, &intent.workspace)
            .await
            .map_err(|_| Denial::Unavailable)?
            .ensure_active()
            .map_err(|_| Denial::PolicyDenied)?;
        let member = self
            .0
            .get_message_by_name::<WorkspaceMember>(&intent.workspace, &intent.owner)
            .await
            .map_err(|_| Denial::Unavailable)?
            .ok_or(Denial::PolicyDenied)?;
        let role = WorkspaceRole::try_from(member.role).map_err(|_| Denial::PolicyDenied)?;
        if !role_satisfies(role, MinWorkspaceRole::User) {
            return Err(Denial::PolicyDenied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        service::TowerToHyperService,
    };
    use serde_json::{Value, json};

    fn intent() -> SandboxIntent {
        SandboxIntent {
            gateway_id: "gateway-a".into(),
            sandbox_id: "sandbox-a".into(),
            workspace: "default".into(),
            owner: "principal-a".into(),
            policy_digest: "policy-a".into(),
            driver: "kubernetes".into(),
            generation: "generation-a".into(),
            auth_epoch: 1,
            expected_spiffe_id: "spiffe://test.example/sandbox-a".into(),
        }
    }

    #[tokio::test]
    async fn bootstrap_owner_authorization_rereads_workspace_membership() {
        let state = crate::grpc::test_support::test_server_state().await;
        let adapter = WorkspaceOwnerAuthorization(state.store.clone());
        let intent = intent();
        assert_eq!(adapter.verify(&intent, 0).await, Err(Denial::PolicyDenied));
        let mut member = WorkspaceMember {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "member-a".into(),
                name: intent.owner.clone(),
                workspace: intent.workspace.clone(),
                ..Default::default()
            }),
            principal_subject: intent.owner.clone(),
            role: WorkspaceRole::User.into(),
        };
        state.store.put_message(&member).await.unwrap();
        adapter.verify(&intent, 0).await.unwrap();
        member.role = WorkspaceRole::Unspecified.into();
        state.store.put_message(&member).await.unwrap();
        assert_eq!(adapter.verify(&intent, 0).await, Err(Denial::PolicyDenied));
    }

    #[tokio::test]
    async fn bootstrap_posture_authority_requires_mtls_and_keeps_proof_local() {
        let directory = tempfile::tempdir().unwrap();
        let (ca, ca_key) = crate::tls_test_utils::generate_test_certs_with_ca(directory.path());
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let key = openshell_crypto::pki::generate_keypair().unwrap();
        let cert = openshell_crypto::pki::signed_by(params, &key, &ca, &ca_key).unwrap();
        let client_path = directory.path().join("client.pem");
        std::fs::write(
            &client_path,
            format!("{}{}", cert.pem(), key.serialize_pem().unwrap()),
        )
        .unwrap();
        let tls = crate::TlsAcceptor::from_files(
            &directory.path().join("server-cert.pem"),
            &directory.path().join("server-key.pem"),
            Some(&directory.path().join("ca.pem")),
            true,
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = Router::new().route(
            "/verify",
            post(|Json(request): Json<Value>| async move {
                if request["stage"] == "bootstrap" {
                    assert_eq!(request["request_evidence"], "fixture-attested-session");
                } else {
                    assert!(request["request_evidence"].is_null());
                    assert_eq!(request["expected_device_id"], "device-a");
                }
                Json(json!({
                    "owner": request["intent"]["owner"],
                    "device_id": "device-a",
                    "device_revision": "revision-a",
                    "challenge": request["challenge"],
                    "issued_at": 100,
                    "expires_at": 120,
                    "compliant": true,
                    "host_id": "host-a",
                    "runtime_identity": request["runtime_identity"],
                    "selectors": ["fixture:selector"],
                    "workload_key_pem": null,
                }))
            }),
        );
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                let acceptor = tls.acceptor();
                let service = TowerToHyperService::new(router.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                });
            }
        });
        let authority = PostureAuthority::new(&BootstrapPostureAuthorityConfig {
            endpoint: format!("https://localhost:{port}/verify"),
            ca_bundle: directory.path().join("ca.pem"),
            client_identity_pem: client_path,
        })
        .unwrap();
        let mut context = AttestationContext {
            stage: Stage::Bootstrap,
            challenge: "challenge-a".into(),
            now: 101,
            intent: intent(),
            runtime_identity: None,
            expected_device_id: None,
            request_evidence: Some("fixture-attested-session".into()),
        };
        let verified = authority.attest(&context).await.unwrap();
        assert_eq!(verified.owner, context.intent.owner);
        assert_eq!(verified.challenge, context.challenge);

        context.stage = Stage::Provider;
        context.runtime_identity = Some("kubernetes://namespace/identity/component".into());
        context.expected_device_id = Some(verified.device_id);
        context.request_evidence = Some("fixture-unconsumed-proof".into());
        let verified = authority.attest(&context).await.unwrap();
        assert_eq!(verified.runtime_identity, context.runtime_identity);
        server.abort();
    }
}
