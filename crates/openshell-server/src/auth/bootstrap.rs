// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway enforcement of bootstrap admission and per-request provider permits.

mod authority;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use openshell_core::bootstrap_authz::{
    AuditRecord, BootstrapGate, DecisionStore, Denial, DeviceAttestationAdapter, Grant,
    JwtWorkloadProofVerifier, RegoAuthorizer, SandboxAuthorizationAdapter, SandboxIntent, Stage,
    UnavailableDeviceAttestation, UnavailableSandboxAuthorization, WorkloadEvidence,
    WorkloadOperation,
};
use openshell_core::config::Config;
use openshell_core::jwt::AuthenticatedSandboxSession;
use openshell_core::proto::{
    Provider, ProviderCredentialTokenGrant, ReportSandboxConfigurationRequest, Sandbox,
    SandboxConfigurationAdmission,
};
use openshell_crypto::tls::spiffe::{SpiffeClientVerifier, VerifiedSpiffeClient};
use openshell_spiffe::SandboxSpiffeIdPrefix;
use rustls::pki_types::UnixTime;
use serde::Serialize;
use tonic::Status;

use super::principal::Principal;
use crate::ServerState;
use crate::persistence::{ObjectId, ObjectWorkspace, Store, WriteCondition};

const AUDIT_TYPE: &str = "bootstrap_authorization_decision";
const GRANT_TYPE: &str = "bootstrap_authorization_grant";
const PROOF_TYPE: &str = "bootstrap_authorization_proof";
pub use openshell_core::bootstrap_identity::WORKLOAD_PROOF_HEADER as PROOF_HEADER;
pub const ACTIVATION_ANNOTATION: &str = "internal.openshell.ai/bootstrap-activation";

pub fn workload_proof(metadata: &tonic::metadata::MetadataMap) -> Option<&str> {
    let mut values = metadata.get_all(PROOF_HEADER).iter();
    let proof = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(proof)
}

#[derive(Serialize)]
struct ConfigurationActivation<'a> {
    decision: Grant,
    admission_decision_id: &'a str,
    gateway_token_id: String,
    configuration_fence: String,
    spiffe_id: String,
}

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
    docker_verifier: Option<SpiffeClientVerifier>,
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
        let tls = config
            .tls
            .as_ref()
            .ok_or("bootstrap_authorization requires gateway TLS")?;
        let jwt = config
            .gateway_jwt
            .as_ref()
            .ok_or("bootstrap_authorization requires gateway_jwt")?;
        if jwt.ttl_secs.is_none() {
            return Err("bootstrap_authorization requires positive gateway JWT TTL".into());
        }
        let (prefix, docker_verifier) = if let Some(raw) = &settings.docker_spiffe_id_prefix {
            if config.compute_driver.as_deref() != Some("docker")
                || config.config_delivery_mode != openshell_core::config::ConfigDeliveryMode::Poll
                || config.spiffe_broker.is_some()
                || config.mtls_auth.enabled
                || config.mtls_auth.operator_enabled
                || tls.require_client_auth
            {
                return Err("Docker bootstrap activation requires the Docker driver, polling, and optional TLS client certificates dedicated to SPIFFE".into());
            }
            let path = tls
                .client_ca_path
                .as_ref()
                .ok_or("Docker bootstrap activation requires a SPIFFE client CA bundle")?;
            let verifier = SpiffeClientVerifier::new(
                openshell_spiffe::trust_domain(raw)
                    .ok_or("invalid Docker SPIFFE trust domain")?
                    .into(),
                load_client_roots(path)?,
            )
            .map_err(|error| error.to_string())?;
            (SandboxSpiffeIdPrefix::parse(raw)?, Some(verifier))
        } else {
            let broker = config
                .spiffe_broker
                .as_ref()
                .ok_or("bootstrap_authorization requires spiffe_broker")?;
            (
                SandboxSpiffeIdPrefix::parse(&broker.spiffe_id_prefix)?,
                None,
            )
        };
        if !(1..=10_000).contains(&settings.timeout_ms)
            || !settings.opa_executable.is_absolute()
            || !settings.opa_executable.is_file()
        {
            return Err("bootstrap_authorization requires an absolute OPA executable and timeout_ms between 1 and 10000".into());
        }
        let (device, sandbox_authorization): (
            Arc<dyn DeviceAttestationAdapter>,
            Arc<dyn SandboxAuthorizationAdapter>,
        ) = match settings.posture_authority.as_ref() {
            Some(config) => (
                Arc::new(authority::PostureAuthority::new(config)?),
                Arc::new(authority::WorkspaceOwnerAuthorization(store.clone())),
            ),
            None => (
                Arc::new(UnavailableDeviceAttestation),
                Arc::new(UnavailableSandboxAuthorization),
            ),
        };
        let gate = BootstrapGate {
            authorizer: Arc::new(
                RegoAuthorizer::new(settings.opa_executable.clone())
                    .map_err(|_| "cannot prepare bootstrap Rego policy")?,
            ),
            device,
            sandbox_authorization,
            proof: Arc::new(JwtWorkloadProofVerifier),
            store: Arc::new(PersistentDecisionStore(store.clone())),
            timeout: Duration::from_millis(settings.timeout_ms),
        };
        Ok(Some(Arc::new(Self {
            gate,
            gateway_id: jwt.gateway_id.clone(),
            prefix,
            store,
            docker_verifier,
        })))
    }

    #[cfg(test)]
    pub(crate) fn with_test_gate(store: Arc<Store>, gate: BootstrapGate) -> Self {
        Self {
            gate,
            gateway_id: "gateway-a".into(),
            prefix: SandboxSpiffeIdPrefix::parse("spiffe://example.org/openshell").unwrap(),
            store,
            docker_verifier: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_docker_verifier(mut self, verifier: SpiffeClientVerifier) -> Self {
        self.docker_verifier = Some(verifier);
        self
    }

    pub fn docker_activation_enabled(&self) -> bool {
        self.docker_verifier.is_some()
    }

    pub fn tls_peer(&self, connection: &rustls::ServerConnection) -> Option<VerifiedSpiffeClient> {
        self.docker_verifier
            .as_ref()?
            .verify_peer(connection, UnixTime::now())
            .ok()
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
        if self.docker_activation_enabled() {
            Self::require_credential_free(sandbox)?;
        }
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
        self.persist_grant(&grant).await?;
        Ok(grant)
    }

    pub(crate) async fn persist_grant(&self, grant: &Grant) -> Result<(), Status> {
        let payload =
            serde_json::to_vec(&grant).map_err(|_| status(Denial::ReplayOrPersistence))?;
        self.store
            .put_if(
                GRANT_TYPE,
                &format!("bootstrap-grant:{}", grant.decision_id),
                &grant.decision_id,
                &grant.intent.workspace,
                &payload,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|_| status(Denial::ReplayOrPersistence))?;
        Ok(())
    }

    pub fn require_credential_free(sandbox: &Sandbox) -> Result<(), Status> {
        if sandbox
            .spec
            .as_ref()
            .is_none_or(|spec| !spec.providers.is_empty())
        {
            return Err(Status::permission_denied(
                "Docker bootstrap activation does not deliver provider credentials",
            ));
        }
        Ok(())
    }

    /// Called after normal configuration admission checks. The caller commits
    /// this decision with the accepted configuration using the same CAS.
    pub async fn authorize_docker_configuration(
        &self,
        state: &ServerState,
        request: &tonic::Request<ReportSandboxConfigurationRequest>,
        sandbox: &Sandbox,
        admission: &SandboxConfigurationAdmission,
    ) -> Result<String, Status> {
        Self::require_credential_free(sandbox)?;
        let mut bearers = request.metadata().get_all("authorization").iter();
        let bearer = bearers
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(openshell_core::auth::strip_bearer_scheme)
            .ok_or_else(|| status(Denial::MissingSignal))?;
        if bearers.next().is_some() {
            return Err(status(Denial::IdentityMismatch));
        }
        let authority = state
            .sandbox_session_jwt_authority
            .as_ref()
            .ok_or_else(|| status(Denial::Unavailable))?;
        let session = authority
            .verify_gateway_token(bearer)
            .map_err(|error| error.status)?;
        if session.sandbox_id.as_str() != sandbox.object_id() {
            return Err(status(Denial::IdentityMismatch));
        }
        super::sandbox_session::authorize_persisted(&state.store, &session)
            .await
            .map_err(|error| error.status)?;
        let grant = session
            .bootstrap
            .as_ref()
            .ok_or_else(|| status(Denial::MissingSignal))?;
        self.verify_grant(grant).await?;
        let intent = self
            .intent(
                state,
                sandbox,
                &grant.intent.owner,
                session.runtime_generation.as_str(),
                session.auth_epoch.get(),
                None,
            )
            .await?;
        let read_observation = || async {
            tokio::time::timeout(self.gate.timeout, state.compute.observe_supervisor(sandbox))
                .await
                .map_err(|_| status(Denial::Timeout))?
        };
        let observation = read_observation().await?;
        let peer = request.extensions().get::<VerifiedSpiffeClient>();
        let configuration_fence = canonical_digest(&(
            &admission.instance_id,
            admission.policy_version,
            &admission.policy_hash,
            admission.config_revision,
            admission.provider_env_revision,
        ))?;
        let decision = self
            .gate
            .activate_docker(
                grant,
                &intent,
                &observation,
                peer,
                &configuration_fence,
                now(),
            )
            .await
            .map_err(status)?;
        let spiffe_id =
            openshell_core::bootstrap_authz::docker_supervisor_spiffe_id(&intent, &observation)
                .map_err(status)?;
        if read_observation().await? != observation {
            return Err(status(Denial::IdentityMismatch));
        }
        super::sandbox_session::authorize_persisted(&state.store, &session)
            .await
            .map_err(|error| error.status)?;
        if self
            .intent(
                state,
                sandbox,
                &grant.intent.owner,
                session.runtime_generation.as_str(),
                session.auth_epoch.get(),
                None,
            )
            .await?
            != intent
        {
            return Err(status(Denial::IdentityMismatch));
        }
        self.verify_grant(grant).await?;
        authority
            .verify_gateway_token(bearer)
            .map_err(|error| error.status)?;
        if decision.expires_at <= now() {
            return Err(status(Denial::StaleEvidence));
        }
        serde_json::to_string(&ConfigurationActivation {
            decision,
            admission_decision_id: &grant.decision_id,
            gateway_token_id: session.token_id.to_string(),
            configuration_fence,
            spiffe_id,
        })
        .map_err(|_| status(Denial::ReplayOrPersistence))
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
        self.workload_permit(
            state,
            session,
            raw_proof,
            audience,
            WorkloadOperation::Provider(resource),
            Some((configuration.0, resource, configuration.1)),
        )
        .await
    }

    pub(crate) async fn renewal_permit(
        &self,
        state: &ServerState,
        session: &AuthenticatedSandboxSession,
        raw_proof: &str,
    ) -> Result<Grant, Status> {
        self.workload_permit(
            state,
            session,
            raw_proof,
            openshell_core::bootstrap_identity::RENEWAL_SVID_AUDIENCE,
            WorkloadOperation::Renew,
            None,
        )
        .await
    }

    async fn workload_permit(
        &self,
        state: &ServerState,
        session: &AuthenticatedSandboxSession,
        raw_proof: &str,
        audience: &str,
        operation: WorkloadOperation<'_>,
        configuration: Option<(&Provider, &str, &ProviderCredentialTokenGrant)>,
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
                configuration,
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
            .workload_permit(
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
                operation,
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
        super::sandbox_session::authorize_persisted(&state.store, session)
            .await
            .map_err(|e| e.status)?;
        self.recheck_evidence(state, session, permit)
            .await
            .map(drop)
    }

    /// Refresh checks lineage separately to permit proof-verified recovery
    /// of a committed successor after a response is lost.
    pub(crate) async fn recheck_evidence(
        &self,
        state: &ServerState,
        session: &AuthenticatedSandboxSession,
        permit: &Grant,
    ) -> Result<u64, Status> {
        if session.expires_at <= now() {
            return Err(status(Denial::StaleEvidence));
        }
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
        let metadata = sandbox
            .metadata
            .as_ref()
            .ok_or_else(|| status(Denial::MissingSignal))?;
        let runtime = super::compute_driver::recorded_runtime(metadata, &grant.intent.driver);
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
            .map_err(status)?;
        if session.expires_at <= now() {
            return Err(status(Denial::StaleEvidence));
        }
        Self::verify_permit_deadline(permit)?;
        Ok(metadata.resource_version)
    }

    pub(crate) fn verify_permit_deadline(permit: &Grant) -> Result<(), Status> {
        if permit.expires_at <= now() {
            return Err(status(Denial::StaleEvidence));
        }
        Ok(())
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
    let persisted = load_grant(store, &grant.decision_id).await?;
    if &persisted != grant || grant.expires_at <= now() {
        return Err(status(Denial::StaleEvidence));
    }
    if let Some(id) = &grant.launch_decision_id {
        let launch = load_grant(store, id).await?;
        if launch.launch_decision_id.is_some()
            || launch.decision_id != *id
            || launch.intent != grant.intent
            || launch.device_id != grant.device_id
            || launch.device_revision != grant.device_revision
        {
            return Err(status(Denial::IdentityMismatch));
        }
    }
    Ok(())
}

async fn load_grant(store: &Store, id: &str) -> Result<Grant, Status> {
    let record = store
        .get(GRANT_TYPE, &format!("bootstrap-grant:{id}"))
        .await
        .map_err(|_| status(Denial::ReplayOrPersistence))?
        .ok_or_else(|| status(Denial::MissingSignal))?;
    serde_json::from_slice(&record.payload).map_err(|_| status(Denial::ReplayOrPersistence))
}

fn load_client_roots(path: &std::path::Path) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in crate::tls::load_certs(path).map_err(|error| error.to_string())? {
        roots.add(cert).map_err(|error| error.to_string())?;
    }
    Ok(roots)
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
