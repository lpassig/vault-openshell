// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verified evidence, policy decisions, and single-use workload proofs.
//!
//! Adapters are trusted verifiers, not sources of caller-authored attributes.
//! The shipped evidence adapter deliberately denies until an operator integrates
//! an attestation authority. No mock verifier is compiled into production.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub const POLICY: &str = include_str!("bootstrap_authz/policy.rego");
pub const BOOTSTRAP_CAPABILITY: &str = "bootstrap";
pub const PROVIDER_CAPABILITY: &str = "provider_access";
pub const ACTIVATION_CAPABILITY: &str = "configuration_activation";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Bootstrap,
    Provider,
    Activation,
}

/// Fixed, secret-free errors. Adapter and policy diagnostics must not escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Denial {
    #[error("bootstrap authorization evidence unavailable")]
    Unavailable,
    #[error("bootstrap authorization timed out")]
    Timeout,
    #[error("bootstrap authorization signal missing")]
    MissingSignal,
    #[error("bootstrap authorization evidence expired or issued in the future")]
    StaleEvidence,
    #[error("bootstrap authorization identity mismatch")]
    IdentityMismatch,
    #[error("bootstrap authorization policy denied")]
    PolicyDenied,
    #[error("bootstrap authorization policy returned an invalid result")]
    InvalidDecision,
    #[error("bootstrap authorization proof rejected")]
    InvalidProof,
    #[error("bootstrap authorization replay or audit persistence failure")]
    ReplayOrPersistence,
}

pub use crate::bootstrap_identity::{Grant, SandboxIntent};

/// Challenge delivered only to a trusted attestation adapter.
#[derive(Clone)]
pub struct AttestationContext {
    pub stage: Stage,
    pub challenge: String,
    pub now: i64,
    pub intent: SandboxIntent,
    pub runtime_identity: Option<String>,
    pub expected_device_id: Option<String>,
    /// Opaque claimant evidence/session reference, never logged or sent to Rego.
    /// Admission verification must bind it to this request and fresh challenge,
    /// rather than merely looking up a device enrolled by the named owner.
    pub request_evidence: Option<String>,
}

/// Result of signature, issuer, audience, freshness and challenge verification.
/// The workload key must be independently attested, never enrolled by bearer alone.
#[derive(Clone)]
pub struct DeviceAttestation {
    pub device_id: String,
    /// Authenticated requester/mission owner independently bound by the verifier.
    pub owner: String,
    pub host_id: Option<String>,
    pub runtime_identity: Option<String>,
    pub challenge: String,
    pub compliant: bool,
    pub issued_at: i64,
    pub expires_at: i64,
    pub device_revision: String,
    /// Independently verified registration/attestor facts; never copied from workload labels.
    pub selectors: BTreeSet<String>,
    pub workload_key_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for DeviceAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAttestation")
            .field("device_id", &self.device_id)
            .field("revision", &self.device_revision)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait DeviceAttestationAdapter: Send + Sync {
    async fn attest(&self, context: &AttestationContext) -> Result<DeviceAttestation, Denial>;
}

/// Production stub. Enabling the gate with no real adapter always denies.
pub struct UnavailableDeviceAttestation;

/// Revalidate owner/mission and policy permission at both gates, including revocation.
#[async_trait]
pub trait SandboxAuthorizationAdapter: Send + Sync {
    async fn verify(&self, intent: &SandboxIntent, now: i64) -> Result<(), Denial>;
}

pub struct UnavailableSandboxAuthorization;

#[async_trait]
impl SandboxAuthorizationAdapter for UnavailableSandboxAuthorization {
    async fn verify(&self, _: &SandboxIntent, _: i64) -> Result<(), Denial> {
        Err(Denial::Unavailable)
    }
}

#[async_trait]
impl DeviceAttestationAdapter for UnavailableDeviceAttestation {
    async fn attest(&self, _: &AttestationContext) -> Result<DeviceAttestation, Denial> {
        Err(Denial::Unavailable)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    pub request_id: String,
    pub parent_decision_id: Option<String>,
    pub stage: Stage,
    pub intent: SandboxIntent,
    pub device_id: String,
    pub device_revision: String,
    pub host_id: Option<String>,
    pub runtime_identity: Option<String>,
    pub spiffe_id: Option<String>,
    pub proof_verified: bool,
    pub selectors: BTreeSet<String>,
    pub resource: String,
    pub now: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionResponse {
    pub allow: bool,
    pub reason: String,
    pub ttl_secs: u64,
    pub scopes: BTreeSet<String>,
}

#[async_trait]
pub trait BootstrapAuthorizer: Send + Sync {
    async fn decide(&self, request: &DecisionRequest) -> Result<DecisionResponse, Denial>;
}

/// Local OPA process, fixed query and gateway-owned policy. Never invokes a shell.
pub struct RegoAuthorizer {
    executable: PathBuf,
    policy: tempfile::NamedTempFile,
}

impl RegoAuthorizer {
    pub fn new(executable: PathBuf) -> Result<Self, Denial> {
        let mut policy = tempfile::NamedTempFile::new().map_err(|_| Denial::Unavailable)?;
        policy
            .write_all(POLICY.as_bytes())
            .map_err(|_| Denial::Unavailable)?;
        Ok(Self { executable, policy })
    }
}

#[async_trait]
impl BootstrapAuthorizer for RegoAuthorizer {
    async fn decide(&self, request: &DecisionRequest) -> Result<DecisionResponse, Denial> {
        let mut child = tokio::process::Command::new(&self.executable)
            .env_clear()
            .args([
                "eval",
                "--strict",
                "--format=json",
                "--stdin-input",
                "--data",
            ])
            .arg(self.policy.path())
            .arg("data.openshell.bootstrap.decision")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Denial::Unavailable)?;
        let input = serde_json::to_vec(request).map_err(|_| Denial::InvalidDecision)?;
        let mut stdin = child.stdin.take().ok_or(Denial::Unavailable)?;
        stdin
            .write_all(&input)
            .await
            .map_err(|_| Denial::Unavailable)?;
        drop(stdin);
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .ok_or(Denial::Unavailable)?
            .take(65_537)
            .read_to_end(&mut output)
            .await
            .map_err(|_| Denial::Unavailable)?;
        if output.len() > 65_536 {
            return Err(Denial::InvalidDecision);
        }
        if !child
            .wait()
            .await
            .map_err(|_| Denial::Unavailable)?
            .success()
        {
            return Err(Denial::InvalidDecision);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&output).map_err(|_| Denial::InvalidDecision)?;
        let results = value
            .get("result")
            .and_then(serde_json::Value::as_array)
            .ok_or(Denial::InvalidDecision)?;
        if results.len() != 1 {
            return Err(Denial::InvalidDecision);
        }
        let expressions = results[0]
            .get("expressions")
            .and_then(serde_json::Value::as_array)
            .ok_or(Denial::InvalidDecision)?;
        if expressions.len() != 1 {
            return Err(Denial::InvalidDecision);
        }
        serde_json::from_value(
            expressions[0]
                .get("value")
                .cloned()
                .ok_or(Denial::InvalidDecision)?,
        )
        .map_err(|_| Denial::InvalidDecision)
    }
}

/// Only an adapter's cryptographically validated SVID may populate this object.
pub struct WorkloadEvidence<'a> {
    pub spiffe_id: &'a str,
    pub audience: &'a str,
    pub expires_at: i64,
    pub runtime_identity: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub decision_id: String,
    pub challenge: String,
    pub sandbox_id: String,
    pub generation: String,
    pub auth_epoch: u64,
    pub gateway_token_id: String,
    pub device_id: String,
    pub runtime_identity: String,
    pub resource: String,
    pub svid_audience: String,
}

pub struct ProofContext<'a> {
    pub grant: &'a Grant,
    pub workload: &'a WorkloadEvidence<'a>,
    pub gateway_token_id: &'a str,
    pub resource: &'a str,
    pub now: i64,
}

#[async_trait]
pub trait WorkloadProofVerifier: Send + Sync {
    async fn verify(
        &self,
        token: &str,
        key_pem: &[u8],
        context: &ProofContext<'_>,
    ) -> Result<ProofClaims, Denial>;
}

pub struct JwtWorkloadProofVerifier;

#[async_trait]
impl WorkloadProofVerifier for JwtWorkloadProofVerifier {
    async fn verify(
        &self,
        token: &str,
        key_pem: &[u8],
        context: &ProofContext<'_>,
    ) -> Result<ProofClaims, Denial> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};
        let key = DecodingKey::from_ed_pem(key_pem).map_err(|_| Denial::InvalidProof)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["openshell-workload-proof"]);
        validation.set_audience(&[context.grant.intent.gateway_id.as_str()]);
        // Enforce time against the gateway's supplied clock, without library leeway.
        validation.validate_exp = false;
        validation.leeway = 0;
        let decoded = openshell_crypto::jwt::decode::<ProofClaims>(token, &key, &validation)
            .map_err(|_| Denial::InvalidProof)?;
        if decoded.header.typ.as_deref() != Some("openshell-bootstrap-proof+jwt") {
            return Err(Denial::InvalidProof);
        }
        let proof = decoded.claims;
        let grant = context.grant;
        if proof.sub != context.workload.spiffe_id
            || proof.decision_id != grant.decision_id
            || proof.challenge != grant.challenge
            || proof.sandbox_id != grant.intent.sandbox_id
            || proof.generation != grant.intent.generation
            || proof.auth_epoch != grant.intent.auth_epoch
            || proof.gateway_token_id != context.gateway_token_id
            || proof.device_id != grant.device_id
            || proof.runtime_identity != context.workload.runtime_identity
            || proof.resource != context.resource
            || proof.svid_audience != context.workload.audience
            || proof.iat > context.now
            || proof.iat < context.now.saturating_sub(30)
            || proof.exp <= context.now
            || proof.exp > proof.iat.saturating_add(30)
            || Uuid::parse_str(&proof.jti).is_err()
        {
            return Err(Denial::InvalidProof);
        }
        Ok(proof)
    }
}

/// Durably write attempts and atomically reserve proof IDs across replicas.
#[async_trait]
pub trait DecisionStore: Send + Sync {
    async fn record(&self, record: &AuditRecord) -> Result<(), Denial>;
    async fn consume_proof(&self, key: &str, expires_at: i64) -> Result<(), Denial>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    pub decision_id: String,
    pub parent_decision_id: Option<String>,
    pub stage: Stage,
    pub intent: SandboxIntent,
    pub device_id: Option<String>,
    pub allow: bool,
    pub reason: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub resource: String,
    pub scopes: BTreeSet<String>,
}

/// All positive results pass independent invariant checks before policy evaluation.
pub struct BootstrapGate {
    pub authorizer: Arc<dyn BootstrapAuthorizer>,
    pub device: Arc<dyn DeviceAttestationAdapter>,
    pub sandbox_authorization: Arc<dyn SandboxAuthorizationAdapter>,
    pub proof: Arc<dyn WorkloadProofVerifier>,
    pub store: Arc<dyn DecisionStore>,
    pub timeout: Duration,
}

impl BootstrapGate {
    pub async fn bootstrap(
        &self,
        intent: SandboxIntent,
        device_evidence: &str,
        now: i64,
    ) -> Result<Grant, Denial> {
        let id = fresh_id()?;
        let challenge = fresh_id()?;
        let context = AttestationContext {
            stage: Stage::Bootstrap,
            challenge: challenge.clone(),
            now,
            intent: intent.clone(),
            runtime_identity: None,
            expected_device_id: None,
            request_evidence: Some(device_evidence.into()),
        };
        let result = tokio::time::timeout(self.timeout, async {
            validate_intent(&intent)?;
            if device_evidence.is_empty()
                || device_evidence.len() > crate::bootstrap_identity::MAX_DEVICE_EVIDENCE_BYTES
            {
                return Err(Denial::MissingSignal);
            }
            self.sandbox_authorization.verify(&intent, now).await?;
            let device = self.device.attest(&context).await?;
            validate_device(&device, &context)?;
            let request = DecisionRequest {
                request_id: id.clone(),
                parent_decision_id: None,
                stage: Stage::Bootstrap,
                intent: intent.clone(),
                device_id: device.device_id.clone(),
                device_revision: device.device_revision.clone(),
                host_id: None,
                runtime_identity: None,
                spiffe_id: None,
                proof_verified: false,
                selectors: BTreeSet::new(),
                resource: BOOTSTRAP_CAPABILITY.into(),
                now,
                expires_at: device.expires_at.min(now.saturating_add(60)),
            };
            let response = self.authorizer.decide(&request).await?;
            let expires_at = validate_response(&request, &response, BOOTSTRAP_CAPABILITY)?;
            Ok(Grant {
                decision_id: id.clone(),
                intent: intent.clone(),
                device_id: device.device_id,
                device_revision: device.device_revision,
                host_id: None,
                runtime_identity: None,
                proof_key_digest: None,
                selectors: BTreeSet::new(),
                challenge,
                issued_at: now,
                expires_at,
                scopes: response.scopes,
            })
        })
        .await
        .unwrap_or(Err(Denial::Timeout));
        self.audit(
            &id,
            None,
            Stage::Bootstrap,
            &intent,
            result.as_ref().ok(),
            &result.as_ref().map(|_| ()),
            now,
            BOOTSTRAP_CAPABILITY,
        )
        .await?;
        result
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn provider(
        &self,
        grant: &Grant,
        intent: &SandboxIntent,
        workload: WorkloadEvidence<'_>,
        gateway_token_id: &str,
        raw_proof: &str,
        resource: &str,
        now: i64,
    ) -> Result<Grant, Denial> {
        let id = fresh_id()?;
        let result = tokio::time::timeout(self.timeout, async {
            if grant.intent != *intent || grant.expires_at <= now || grant.issued_at > now {
                return Err(Denial::StaleEvidence);
            }
            self.sandbox_authorization.verify(intent, now).await?;
            if !grant.scopes.contains(BOOTSTRAP_CAPABILITY)
                || resource.is_empty()
                || gateway_token_id.is_empty()
            {
                return Err(Denial::MissingSignal);
            }
            if workload.spiffe_id != intent.expected_spiffe_id
                || workload.runtime_identity.is_empty()
                || workload.audience.is_empty()
                || workload.expires_at <= now
            {
                return Err(Denial::IdentityMismatch);
            }
            if raw_proof.is_empty() || raw_proof.len() > 16_384 {
                return Err(Denial::InvalidProof);
            }
            let context = AttestationContext {
                stage: Stage::Provider,
                challenge: id.clone(),
                now,
                intent: intent.clone(),
                runtime_identity: Some(workload.runtime_identity.into()),
                expected_device_id: Some(grant.device_id.clone()),
                request_evidence: Some(raw_proof.into()),
            };
            let device = self.device.attest(&context).await?;
            validate_device(&device, &context)?;
            if device.device_revision != grant.device_revision {
                return Err(Denial::IdentityMismatch);
            }
            if device.selectors.is_empty()
                || device.host_id.as_deref().is_none_or(str::is_empty)
                || device.runtime_identity.as_deref() != Some(workload.runtime_identity)
            {
                return Err(Denial::MissingSignal);
            }
            let key = device
                .workload_key_pem
                .as_deref()
                .ok_or(Denial::MissingSignal)?;
            let proof_key_digest = digest(key)?;
            let proof = self
                .proof
                .verify(
                    raw_proof,
                    key,
                    &ProofContext {
                        grant,
                        workload: &workload,
                        gateway_token_id,
                        resource,
                        now,
                    },
                )
                .await?;
            let request = DecisionRequest {
                request_id: id.clone(),
                parent_decision_id: Some(grant.decision_id.clone()),
                stage: Stage::Provider,
                intent: intent.clone(),
                device_id: device.device_id.clone(),
                device_revision: device.device_revision.clone(),
                host_id: device.host_id.clone(),
                runtime_identity: Some(workload.runtime_identity.into()),
                spiffe_id: Some(workload.spiffe_id.into()),
                proof_verified: true,
                selectors: device.selectors.clone(),
                resource: resource.into(),
                now,
                expires_at: grant
                    .expires_at
                    .min(device.expires_at)
                    .min(workload.expires_at)
                    .min(proof.exp),
            };
            let response = self.authorizer.decide(&request).await?;
            let expires_at = validate_response(&request, &response, PROVIDER_CAPABILITY)?;
            let replay_key = digest(format!("{}:{}", grant.decision_id, proof.jti).as_bytes())?;
            self.store.consume_proof(&replay_key, proof.exp).await?;
            Ok(Grant {
                decision_id: id.clone(),
                intent: intent.clone(),
                device_id: device.device_id,
                device_revision: device.device_revision,
                host_id: device.host_id,
                runtime_identity: Some(workload.runtime_identity.into()),
                proof_key_digest: Some(proof_key_digest),
                selectors: device.selectors,
                challenge: String::new(),
                issued_at: now,
                expires_at,
                scopes: response.scopes,
            })
        })
        .await
        .unwrap_or(Err(Denial::Timeout));
        self.audit(
            &id,
            Some(&grant.decision_id),
            Stage::Provider,
            intent,
            result.as_ref().ok(),
            &result.as_ref().map(|_| ()),
            now,
            resource,
        )
        .await?;
        result
    }

    /// Authorize one configuration acknowledgement on an authenticated SPIFFE
    /// connection. This capability confers no provider credential access.
    pub async fn activate_docker(
        &self,
        grant: &Grant,
        intent: &SandboxIntent,
        observation: &crate::proto::compute::v1::SupervisorRuntimeObservation,
        peer: Option<&openshell_crypto::tls::spiffe::VerifiedSpiffeClient>,
        configuration_fence: &str,
        now: i64,
    ) -> Result<Grant, Denial> {
        let id = fresh_id()?;
        let result = tokio::time::timeout(self.timeout, async {
            if grant.intent != *intent || grant.expires_at <= now || grant.issued_at > now {
                return Err(Denial::StaleEvidence);
            }
            if !grant.scopes.contains(BOOTSTRAP_CAPABILITY) || configuration_fence.is_empty() {
                return Err(Denial::MissingSignal);
            }
            let spiffe_id = docker_supervisor_spiffe_id(intent, observation)?;
            let unix_time = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(
                u64::try_from(now).map_err(|_| Denial::StaleEvidence)?,
            ));
            let certificate_expiry = peer
                .ok_or(Denial::MissingSignal)?
                .authorize(&spiffe_id, unix_time)
                .map_err(|_| Denial::InvalidProof)?;
            self.sandbox_authorization.verify(intent, now).await?;
            let context = AttestationContext {
                stage: Stage::Activation,
                challenge: id.clone(),
                now,
                intent: intent.clone(),
                runtime_identity: Some(observation.runtime_identity.clone()),
                expected_device_id: Some(grant.device_id.clone()),
                request_evidence: None,
            };
            let device = self.device.attest(&context).await?;
            validate_device(&device, &context)?;
            if device.device_revision != grant.device_revision
                || device.runtime_identity.as_ref() != context.runtime_identity.as_ref()
                || device.host_id.as_deref().is_none_or(str::is_empty)
                || device.selectors.is_empty()
            {
                return Err(Denial::IdentityMismatch);
            }
            let request = DecisionRequest {
                request_id: id.clone(),
                parent_decision_id: Some(grant.decision_id.clone()),
                stage: Stage::Activation,
                intent: intent.clone(),
                device_id: device.device_id.clone(),
                device_revision: device.device_revision.clone(),
                host_id: device.host_id.clone(),
                runtime_identity: context.runtime_identity.clone(),
                spiffe_id: Some(spiffe_id),
                proof_verified: true,
                selectors: device.selectors.clone(),
                resource: configuration_fence.into(),
                now,
                expires_at: grant
                    .expires_at
                    .min(device.expires_at)
                    .min(certificate_expiry),
            };
            let response = self.authorizer.decide(&request).await?;
            let expires_at = validate_response(&request, &response, ACTIVATION_CAPABILITY)?;
            Ok(Grant {
                decision_id: id.clone(),
                intent: intent.clone(),
                device_id: device.device_id,
                device_revision: device.device_revision,
                host_id: device.host_id,
                runtime_identity: context.runtime_identity,
                proof_key_digest: None,
                selectors: device.selectors,
                challenge: String::new(),
                issued_at: now,
                expires_at,
                scopes: response.scopes,
            })
        })
        .await
        .unwrap_or(Err(Denial::Timeout));
        self.audit(
            &id,
            Some(&grant.decision_id),
            Stage::Activation,
            intent,
            result.as_ref().ok(),
            &result.as_ref().map(|_| ()),
            now,
            configuration_fence,
        )
        .await?;
        result
    }

    /// Re-attest after asynchronous work, before minting and before delivery.
    pub async fn recheck(
        &self,
        permit: &Grant,
        intent: &SandboxIntent,
        now: i64,
    ) -> Result<(), Denial> {
        tokio::time::timeout(self.timeout, async {
            if permit.intent != *intent || permit.expires_at <= now {
                return Err(Denial::StaleEvidence);
            }
            self.sandbox_authorization.verify(intent, now).await?;
            let context = AttestationContext {
                stage: Stage::Provider,
                challenge: fresh_id()?,
                now,
                intent: intent.clone(),
                runtime_identity: permit.runtime_identity.clone(),
                expected_device_id: Some(permit.device_id.clone()),
                request_evidence: None,
            };
            let device = self.device.attest(&context).await?;
            validate_device(&device, &context)?;
            if device.selectors != permit.selectors
                || device.device_revision != permit.device_revision
                || device.host_id != permit.host_id
                || device.runtime_identity != permit.runtime_identity
                || Some(digest(
                    device
                        .workload_key_pem
                        .as_deref()
                        .ok_or(Denial::MissingSignal)?,
                )?) != permit.proof_key_digest
            {
                return Err(Denial::IdentityMismatch);
            }
            Ok(())
        })
        .await
        .unwrap_or(Err(Denial::Timeout))
    }

    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        id: &str,
        parent: Option<&str>,
        stage: Stage,
        intent: &SandboxIntent,
        grant: Option<&Grant>,
        result: &Result<(), &Denial>,
        now: i64,
        resource: &str,
    ) -> Result<(), Denial> {
        let record = AuditRecord {
            decision_id: id.into(),
            parent_decision_id: parent.map(str::to_owned),
            stage,
            intent: intent.clone(),
            device_id: grant.map(|v| v.device_id.clone()),
            allow: result.is_ok(),
            reason: result
                .as_ref()
                .map_or_else(ToString::to_string, |()| "allowed".into()),
            issued_at: now,
            expires_at: grant.map_or(now, |v| v.expires_at),
            resource: resource.into(),
            scopes: grant.map_or_else(BTreeSet::new, |v| v.scopes.clone()),
        };
        let persisted = tokio::time::timeout(self.timeout, self.store.record(&record))
            .await
            .unwrap_or(Err(Denial::Timeout));
        // A failed durable write must remain observable in the independent log
        // sink, and must never be reported there as permission to issue a token.
        let allow = record.allow && persisted.is_ok();
        let reason = persisted
            .as_ref()
            .map_or_else(ToString::to_string, |()| record.reason.clone());
        tracing::info!(target: "openshell::bootstrap_authz", decision_id = %record.decision_id,
            parent_decision_id = ?record.parent_decision_id, stage = ?record.stage,
            sandbox_id = %intent.sandbox_id, generation = %intent.generation,
            device_id = ?record.device_id, allow, policy_allow = record.allow, reason,
            expires_at = record.expires_at, "bootstrap authorization decision");
        persisted
    }
}

fn digest(bytes: &[u8]) -> Result<String, Denial> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(openshell_crypto::sha256(bytes).map_err(|_| Denial::Unavailable)?))
}

/// Expected X.509 identity for the sandbox's current Docker supervisor. The
/// observation must be read from the configured, trusted compute driver.
pub fn docker_supervisor_spiffe_id(
    intent: &SandboxIntent,
    observation: &crate::proto::compute::v1::SupervisorRuntimeObservation,
) -> Result<String, Denial> {
    if intent.driver != "docker"
        || observation.sandbox_id != intent.sandbox_id
        || observation.generation != intent.generation
        || observation.auth_epoch != intent.auth_epoch
    {
        return Err(Denial::IdentityMismatch);
    }
    let container_id = observation
        .runtime_identity
        .strip_prefix("docker://")
        .filter(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(Denial::IdentityMismatch)?;
    let id = format!(
        "{}/generation/{}/epoch/{}/supervisor/{container_id}",
        intent.expected_spiffe_id, intent.generation, intent.auth_epoch
    );
    openshell_spiffe::SandboxSpiffeIdPrefix::parse(&id).map_err(|_| Denial::IdentityMismatch)?;
    Ok(id)
}

fn fresh_id() -> Result<String, Denial> {
    Ok(
        Uuid::from_bytes(openshell_crypto::random_bytes::<16>().map_err(|_| Denial::Unavailable)?)
            .to_string(),
    )
}

fn validate_intent(intent: &SandboxIntent) -> Result<(), Denial> {
    if [
        &intent.gateway_id,
        &intent.sandbox_id,
        &intent.workspace,
        &intent.owner,
        &intent.policy_digest,
        &intent.driver,
        &intent.generation,
        &intent.expected_spiffe_id,
    ]
    .iter()
    .any(|v| v.is_empty())
        || intent.auth_epoch == 0
    {
        return Err(Denial::MissingSignal);
    }
    let prefix = intent
        .expected_spiffe_id
        .strip_suffix(&format!(
            "/gateway/{}/sandbox/{}",
            intent.gateway_id, intent.sandbox_id
        ))
        .ok_or(Denial::IdentityMismatch)?;
    openshell_spiffe::SandboxSpiffeIdPrefix::parse(prefix).map_err(|_| Denial::IdentityMismatch)?;
    Ok(())
}

fn validate_device(device: &DeviceAttestation, context: &AttestationContext) -> Result<(), Denial> {
    if device.owner != context.intent.owner {
        return Err(Denial::IdentityMismatch);
    }
    if device.device_id.is_empty() || device.device_revision.is_empty() || !device.compliant {
        return Err(Denial::MissingSignal);
    }
    if device.expires_at <= context.now
        || device.issued_at > context.now
        || device.issued_at < context.now.saturating_sub(60)
    {
        return Err(Denial::StaleEvidence);
    }
    if device.challenge != context.challenge
        || context
            .expected_device_id
            .as_ref()
            .is_some_and(|id| id != &device.device_id)
    {
        return Err(Denial::IdentityMismatch);
    }
    Ok(())
}

fn validate_response(
    request: &DecisionRequest,
    response: &DecisionResponse,
    capability: &str,
) -> Result<i64, Denial> {
    if !response.allow {
        return Err(Denial::PolicyDenied);
    }
    if response.reason.is_empty()
        || response.reason.len() > 128
        || response.ttl_secs == 0
        || response.ttl_secs > 60
        || response.scopes != BTreeSet::from([capability.to_string()])
    {
        return Err(Denial::InvalidDecision);
    }
    let expires_at =
        request.expires_at.min(request.now.saturating_add(
            i64::try_from(response.ttl_secs).map_err(|_| Denial::InvalidDecision)?,
        ));
    if expires_at <= request.now {
        return Err(Denial::StaleEvidence);
    }
    Ok(expires_at)
}

#[cfg(test)]
mod tests;
