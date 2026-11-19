// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway enforcement of bootstrap admission and per-request provider permits.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use openshell_core::bootstrap_authz::{
    AuditRecord, BootstrapGate, DecisionStore, Denial, Grant, JwtWorkloadProofVerifier,
    RegoAuthorizer, SandboxIntent, Stage, UnavailableDeviceAttestation,
    UnavailableSandboxAuthorization, WorkloadEvidence,
};
use openshell_core::config::Config;
use openshell_core::jwt::AuthenticatedSandboxSession;
use openshell_core::proto::{Provider, ProviderCredentialTokenGrant, Sandbox};
use openshell_spiffe::SandboxSpiffeIdPrefix;
use serde::Serialize;
use tonic::Status;

use super::principal::Principal;
use crate::ServerState;
use crate::persistence::{ObjectId, ObjectWorkspace, Store, WriteCondition};

const AUDIT_TYPE: &str = "bootstrap_authorization_decision";
const GRANT_TYPE: &str = "bootstrap_authorization_grant";
const PROOF_TYPE: &str = "bootstrap_authorization_proof";
pub const PROOF_HEADER: &str = "x-openshell-workload-proof";
pub const DEVICE_HEADER: &str = "x-openshell-device-evidence";

pub struct PersistentDecisionStore(pub Arc<Store>);

#[async_trait]
impl DecisionStore for PersistentDecisionStore {
    async fn record(&self, record: &AuditRecord) -> Result<(), Denial> {
        let payload = serde_json::to_vec(record).map_err(|_| Denial::ReplayOrPersistence)?;
        self.0
            .put_if(
                AUDIT_TYPE,
                &format!("bootstrap-decision:{}", record.decision_id),
                &record.decision_id,
                &record.intent.workspace,
                &payload,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|_| Denial::ReplayOrPersistence)?;
        Ok(())
    }

    async fn consume_proof(&self, key: &str, expires_at: i64) -> Result<(), Denial> {
        self.0
            .put_if(
                PROOF_TYPE,
                &format!("bootstrap-proof:{key}"),
                key,
                "",
                &expires_at.to_be_bytes(),
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|_| Denial::ReplayOrPersistence)?;
        Ok(())
    }
}

pub struct BootstrapRuntime {
    pub gate: BootstrapGate,
    gateway_id: String,
    prefix: SandboxSpiffeIdPrefix,
    store: Arc<Store>,
}

impl std::fmt::Debug for BootstrapRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapRuntime")
            .field("gateway_id", &self.gateway_id)
            .finish_non_exhaustive()
    }
}

impl BootstrapRuntime {
    pub fn from_config(config: &Config, store: Arc<Store>) -> Result<Option<Arc<Self>>, String> {
        let Some(settings) = config
            .bootstrap_authorization
            .as_ref()
            .filter(|s| s.enabled)
        else {
            return Ok(None);
        };
        if config.tls.is_none() {
            return Err("bootstrap_authorization requires gateway TLS".into());
        }
        let jwt = config
            .gateway_jwt
            .as_ref()
            .ok_or("bootstrap_authorization requires gateway_jwt")?;
        if jwt.ttl_secs.is_none() {
            return Err("bootstrap_authorization requires positive gateway JWT TTL".into());
        }
        let broker = config
            .spiffe_broker
            .as_ref()
            .ok_or("bootstrap_authorization requires spiffe_broker")?;
        if !(1..=10_000).contains(&settings.timeout_ms)
            || !settings.opa_executable.is_absolute()
            || !settings.opa_executable.is_file()
        {
            return Err("bootstrap_authorization requires an absolute OPA executable and timeout_ms between 1 and 10000".into());
        }
        let gate = BootstrapGate {
            authorizer: Arc::new(
                RegoAuthorizer::new(settings.opa_executable.clone())
                    .map_err(|_| "cannot prepare bootstrap Rego policy")?,
            ),
            device: Arc::new(UnavailableDeviceAttestation),
            sandbox_authorization: Arc::new(UnavailableSandboxAuthorization),
            proof: Arc::new(JwtWorkloadProofVerifier),
            store: Arc::new(PersistentDecisionStore(store.clone())),
            timeout: Duration::from_millis(settings.timeout_ms),
        };
        Ok(Some(Arc::new(Self {
            gate,
            gateway_id: jwt.gateway_id.clone(),
            prefix: SandboxSpiffeIdPrefix::parse(&broker.spiffe_id_prefix)?,
            store,
        })))
    }

    #[cfg(test)]
    pub(crate) fn with_test_gate(store: Arc<Store>, gate: BootstrapGate) -> Self {
        Self {
            gate,
            gateway_id: "gateway-a".into(),
            prefix: SandboxSpiffeIdPrefix::parse("spiffe://example.org/openshell").unwrap(),
            store,
        }
    }

    /// The caller already passed workspace create authorization and canonical policy validation.
    pub async fn admit(
        &self,
        state: &ServerState,
        principal: &Principal,
        sandbox: &Sandbox,
        identity: &super::sandbox_session::PersistedSandboxIdentity,
        device_evidence: &str,
    ) -> Result<Grant, Status> {
        let owner = principal
            .user_identity()
            .filter(|i| i.provider != super::identity::IdentityProvider::LocalDev)
            .map(|i| i.subject.clone())
            .ok_or_else(|| {
                Status::permission_denied("bootstrap admission requires an authenticated owner")
            })?;
        let intent = self
            .intent(
                state,
                sandbox,
                &owner,
                identity.runtime_generation.as_str(),
                identity.auth_epoch.get(),
                None,
            )
            .await?;
        let grant = self
            .gate
            .bootstrap(intent, device_evidence, now())
            .await
            .map_err(status)?;
        let payload =
            serde_json::to_vec(&grant).map_err(|_| status(Denial::ReplayOrPersistence))?;
        self.store
            .put_if(
                GRANT_TYPE,
                &format!("bootstrap-grant:{}", grant.decision_id),
                &grant.decision_id,
                sandbox.object_workspace(),
                &payload,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|_| status(Denial::ReplayOrPersistence))?;
        Ok(grant)
    }

    pub async fn verify_grant(&self, grant: &Grant) -> Result<(), Status> {
        verify_persisted_grant(&self.store, grant).await
    }

    /// Trusted revocation integrations may remove a grant; every request rereads it.
    pub async fn revoke(&self, decision_id: &str) -> Result<(), Status> {
        self.store
            .delete(GRANT_TYPE, &format!("bootstrap-grant:{decision_id}"))
            .await
            .map_err(|_| status(Denial::ReplayOrPersistence))?;
        Ok(())
    }

    async fn intent(
        &self,
        state: &ServerState,
        sandbox: &Sandbox,
        owner: &str,
        generation: &str,
        auth_epoch: u64,
        expected_configuration: Option<(&Provider, &str, &ProviderCredentialTokenGrant)>,
    ) -> Result<SandboxIntent, Status> {
        let inputs =
            crate::grpc::policy::resolve_sandbox_create_runtime_inputs(state, sandbox).await?;
        let mut providers = Vec::new();
        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(&state.store, sandbox.object_workspace())
            .await?;
        let mut configuration_matched = expected_configuration.is_none();
        for name in sandbox
            .spec
            .as_ref()
            .map(|s| s.providers.as_slice())
            .unwrap_or_default()
        {
            let provider = state
                .store
                .get_message_by_name::<Provider>(sandbox.object_workspace(), name)
                .await
                .map_err(|_| status(Denial::Unavailable))?
                .ok_or_else(|| status(Denial::MissingSignal))?;
            let profile = crate::grpc::provider::get_provider_type_profile_for_scope(
                &catalog,
                &provider.r#type,
                &provider.profile_workspace,
            )
            .ok_or_else(|| status(Denial::MissingSignal))?;
            if let Some((expected_provider, key, expected_grant)) = expected_configuration
                && expected_provider.object_id() == provider.object_id()
            {
                // Bind the exact parameters actually used by the RPC to the same
                // profile snapshot whose digest is compared with admission.
                // Merely checking the current digest could approve stale parameters.
                let mut credentials = std::collections::HashMap::new();
                crate::grpc::provider::insert_dynamic_credentials_for_profile(
                    &mut credentials,
                    &profile,
                    name,
                    provider.object_id(),
                )?;
                if expected_provider != &provider
                    || credentials.get(key).and_then(|c| c.token_grant.as_ref())
                        != Some(expected_grant)
                {
                    return Err(status(Denial::IdentityMismatch));
                }
                configuration_matched = true;
            }
            providers.push((
                provider.object_id().to_owned(),
                provider.metadata.as_ref().map(|m| m.resource_version),
                proto_value(&profile.to_proto(), "openshell.v1.ProviderProfile")?,
            ));
        }
        if !configuration_matched {
            return Err(status(Denial::IdentityMismatch));
        }
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| status(Denial::MissingSignal))?;
        let policy = inputs
            .effective_policy
            .ok_or_else(|| status(Denial::MissingSignal))?;
        let digest = canonical_digest(&(
            proto_value(spec, "openshell.v1.SandboxSpec")?,
            proto_value(&policy, "openshell.sandbox.v1.SandboxPolicy")?,
            providers,
        ))?;
        Ok(SandboxIntent {
            gateway_id: self.gateway_id.clone(),
            sandbox_id: sandbox.object_id().into(),
            workspace: sandbox.object_workspace().into(),
            owner: owner.into(),
            policy_digest: digest,
            driver: state.compute.configured_driver_name().into(),
            generation: generation.into(),
            auth_epoch,
            expected_spiffe_id: self
                .prefix
                .sandbox_spiffe_id(&self.gateway_id, sandbox.object_id())
                .map_err(|_| status(Denial::IdentityMismatch))?,
        })
    }

    /// Runs before any provider driver read or token-cache access. The SVID is evidence only.
    pub async fn provider_permit(
        &self,
        state: &ServerState,
        session: &AuthenticatedSandboxSession,
        raw_proof: &str,
        resource: &str,
        audience: &str,
        configuration: (&Provider, &ProviderCredentialTokenGrant),
    ) -> Result<Grant, Status> {
        let grant = session
            .bootstrap
            .as_ref()
            .ok_or_else(|| status(Denial::MissingSignal))?;
        self.verify_grant(grant).await?;
        let sandbox = state
            .store
            .get_message::<Sandbox>(session.sandbox_id.as_str())
            .await
            .map_err(|_| status(Denial::Unavailable))?
            .ok_or_else(|| status(Denial::MissingSignal))?;
        let intent = self
            .intent(
                state,
                &sandbox,
                &grant.intent.owner,
                session.runtime_generation.as_str(),
                session.auth_epoch.get(),
                Some((configuration.0, resource, configuration.1)),
            )
            .await?;
        let runtime = sandbox
            .metadata
            .as_ref()
            .and_then(|metadata| {
                super::compute_driver::recorded_runtime(metadata, &grant.intent.driver)
            })
            .ok_or_else(|| status(Denial::MissingSignal))?;
        let identity = state
            .sandbox_identity
            .as_deref()
            .ok_or_else(|| status(Denial::MissingSignal))?;
        let svid = tokio::time::timeout(
            self.gate.timeout,
            identity.fetch_jwt_svid(
                &self.gateway_id,
                session.sandbox_id.as_str(),
                audience,
                runtime,
            ),
        )
        .await
        .map_err(|_| status(Denial::Timeout))?
        .map_err(|_| status(Denial::IdentityMismatch))?;
        self.gate
            .provider(
                grant,
                &intent,
                WorkloadEvidence {
                    spiffe_id: &svid.spiffe_id,
                    audience,
                    expires_at: svid.expires_at,
                    runtime_identity: runtime,
                },
                &session.token_id.to_string(),
                raw_proof,
                resource,
                now(),
            )
            .await
            .map_err(status)
    }

    pub async fn recheck(
        &self,
        state: &ServerState,
        session: &AuthenticatedSandboxSession,
        permit: &Grant,
    ) -> Result<(), Status> {
        let grant = session
            .bootstrap
            .as_ref()
            .ok_or_else(|| status(Denial::MissingSignal))?;
        self.verify_grant(grant).await?;
        super::sandbox_session::authorize_persisted(&state.store, session)
            .await
            .map_err(|e| e.status)?;
        let sandbox = state
            .store
            .get_message::<Sandbox>(session.sandbox_id.as_str())
            .await
            .map_err(|_| status(Denial::Unavailable))?
            .ok_or_else(|| status(Denial::MissingSignal))?;
        let runtime = sandbox.metadata.as_ref().and_then(|metadata| {
            super::compute_driver::recorded_runtime(metadata, &grant.intent.driver)
        });
        if runtime.is_none() || runtime != permit.runtime_identity.as_deref() {
            return Err(status(Denial::IdentityMismatch));
        }
        let intent = self
            .intent(
                state,
                &sandbox,
                &grant.intent.owner,
                session.runtime_generation.as_str(),
                session.auth_epoch.get(),
                None,
            )
            .await?;
        self.gate
            .recheck(permit, &intent, now())
            .await
            .map_err(status)
    }

    /// Until a path can authenticate caller key possession, it has no credential capability.
    pub async fn reject(&self, sandbox_id: &str, resource: &str) -> Status {
        let id = uuid::Uuid::new_v4().to_string();
        let intent = SandboxIntent {
            gateway_id: self.gateway_id.clone(),
            sandbox_id: sandbox_id.into(),
            workspace: String::new(),
            owner: String::new(),
            policy_digest: String::new(),
            driver: String::new(),
            generation: String::new(),
            auth_epoch: 0,
            expected_spiffe_id: String::new(),
        };
        let record = AuditRecord {
            decision_id: id,
            parent_decision_id: None,
            stage: Stage::Provider,
            intent,
            device_id: None,
            allow: false,
            reason: "unsupported_credential_path".into(),
            issued_at: now(),
            expires_at: now(),
            resource: resource.into(),
            scopes: std::collections::BTreeSet::new(),
        };
        if !matches!(
            tokio::time::timeout(self.gate.timeout, self.gate.store.record(&record)).await,
            Ok(Ok(()))
        ) {
            return status(Denial::ReplayOrPersistence);
        }
        tracing::info!(target: "openshell::bootstrap_authz", decision_id = %record.decision_id,
            sandbox_id, resource, allow = false, reason = "unsupported_credential_path", "bootstrap authorization decision");
        Status::permission_denied(
            "bootstrap authorization requires a proof-capable credential path",
        )
    }
}

/// Check the gateway-owned decision independently of the sandbox record and JWT.
pub async fn verify_persisted_grant(store: &Store, grant: &Grant) -> Result<(), Status> {
    let record = store
        .get(
            GRANT_TYPE,
            &format!("bootstrap-grant:{}", grant.decision_id),
        )
        .await
        .map_err(|_| status(Denial::ReplayOrPersistence))?
        .ok_or_else(|| status(Denial::MissingSignal))?;
    let persisted: Grant =
        serde_json::from_slice(&record.payload).map_err(|_| status(Denial::ReplayOrPersistence))?;
    if &persisted != grant || grant.expires_at <= now() {
        return Err(status(Denial::StaleEvidence));
    }
    Ok(())
}

fn canonical_digest(value: &impl Serialize) -> Result<String, Status> {
    fn sort(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.sort_keys();
                for value in map.values_mut() {
                    sort(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    sort(value);
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).map_err(|_| status(Denial::Unavailable))?;
    sort(&mut value);
    let bytes = serde_json::to_vec(&value).map_err(|_| status(Denial::Unavailable))?;
    openshell_crypto::sha256(&bytes)
        .map(hex::encode)
        .map_err(|_| status(Denial::Unavailable))
}

fn proto_value(message: &impl prost::Message, name: &str) -> Result<serde_json::Value, Status> {
    let pool = prost_reflect::DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
        .map_err(|_| status(Denial::Unavailable))?;
    let descriptor = pool
        .get_message_by_name(name)
        .ok_or_else(|| status(Denial::Unavailable))?;
    let message =
        prost_reflect::DynamicMessage::decode(descriptor, message.encode_to_vec().as_slice())
            .map_err(|_| status(Denial::Unavailable))?;
    serde_json::to_value(message).map_err(|_| status(Denial::Unavailable))
}

fn status(reason: Denial) -> Status {
    Status::permission_denied(reason.to_string())
}
pub fn now() -> i64 {
    crate::persistence::current_time_ms() / 1000
}
