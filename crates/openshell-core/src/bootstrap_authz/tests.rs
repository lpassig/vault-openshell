// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Mutex;

const NOW: i64 = 1_800_000_000;

#[derive(Default)]
struct MemoryStore {
    records: Mutex<Vec<AuditRecord>>,
    proofs: Mutex<BTreeSet<String>>,
}

#[async_trait]
impl DecisionStore for MemoryStore {
    async fn record(&self, record: &AuditRecord) -> Result<(), Denial> {
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
    async fn consume_proof(&self, key: &str, _: i64) -> Result<(), Denial> {
        if !self.proofs.lock().unwrap().insert(key.into()) {
            return Err(Denial::ReplayOrPersistence);
        }
        Ok(())
    }
}

struct MockDevice {
    public_key: Vec<u8>,
    lifetime: i64,
    missing: bool,
}

struct FailingStore {
    fail_audit: bool,
}

#[async_trait]
impl DecisionStore for FailingStore {
    async fn record(&self, _: &AuditRecord) -> Result<(), Denial> {
        if self.fail_audit {
            Err(Denial::ReplayOrPersistence)
        } else {
            Ok(())
        }
    }
    async fn consume_proof(&self, _: &str, _: i64) -> Result<(), Denial> {
        Err(Denial::ReplayOrPersistence)
    }
}

#[async_trait]
impl DeviceAttestationAdapter for MockDevice {
    async fn attest(&self, context: &AttestationContext) -> Result<DeviceAttestation, Denial> {
        Ok(DeviceAttestation {
            owner: context.intent.owner.clone(),
            device_id: if self.missing {
                String::new()
            } else {
                "device-a".into()
            },
            host_id: Some("host-a".into()),
            runtime_identity: context.runtime_identity.clone(),
            challenge: context.challenge.clone(),
            compliant: true,
            issued_at: NOW,
            expires_at: NOW + self.lifetime,
            device_revision: "enrollment-v1".into(),
            selectors: BTreeSet::from(["test:verified-selector".into()]),
            workload_key_pem: Some(self.public_key.clone()),
        })
    }
}

struct MockAuthorizer {
    allow: bool,
    delay: Duration,
}

struct MockSandboxAuthorization;

#[async_trait]
impl SandboxAuthorizationAdapter for MockSandboxAuthorization {
    async fn verify(&self, _: &SandboxIntent, _: i64) -> Result<(), Denial> {
        Ok(())
    }
}

#[async_trait]
impl BootstrapAuthorizer for MockAuthorizer {
    async fn decide(&self, request: &DecisionRequest) -> Result<DecisionResponse, Denial> {
        tokio::time::sleep(self.delay).await;
        Ok(DecisionResponse {
            allow: self.allow,
            reason: "test_policy".into(),
            ttl_secs: 30,
            scopes: BTreeSet::from([match request.stage {
                Stage::Bootstrap => BOOTSTRAP_CAPABILITY,
                Stage::Provider => PROVIDER_CAPABILITY,
                Stage::Activation => ACTIVATION_CAPABILITY,
            }
            .into()]),
        })
    }
}

fn intent() -> SandboxIntent {
    SandboxIntent {
        gateway_id: "gateway-a".into(),
        sandbox_id: "sandbox-a".into(),
        workspace: "default".into(),
        owner: "user-a".into(),
        policy_digest: "policy-v1".into(),
        driver: "kubernetes".into(),
        generation: "generation-a".into(),
        auth_epoch: 1,
        expected_spiffe_id: "spiffe://example.org/openshell/gateway/gateway-a/sandbox/sandbox-a"
            .into(),
    }
}

fn fixture() -> (BootstrapGate, Arc<MemoryStore>, jsonwebtoken::EncodingKey) {
    let key = openshell_crypto::pki::generate_jwt_keypair().unwrap();
    let private =
        jsonwebtoken::EncodingKey::from_ed_pem(key.serialize_pem().unwrap().as_bytes()).unwrap();
    let store = Arc::new(MemoryStore::default());
    (
        BootstrapGate {
            authorizer: Arc::new(MockAuthorizer {
                allow: true,
                delay: Duration::ZERO,
            }),
            sandbox_authorization: Arc::new(MockSandboxAuthorization),
            device: Arc::new(MockDevice {
                public_key: key.public_key_pem().into_bytes(),
                lifetime: 120,
                missing: false,
            }),
            proof: Arc::new(JwtWorkloadProofVerifier),
            store: store.clone(),
            timeout: Duration::from_secs(1),
        },
        store,
        private,
    )
}

fn proof(grant: &Grant, key: &jsonwebtoken::EncodingKey, nonce: Uuid) -> String {
    let claims = ProofClaims {
        iss: "openshell-workload-proof".into(),
        sub: grant.intent.expected_spiffe_id.clone(),
        aud: grant.intent.gateway_id.clone(),
        iat: NOW,
        exp: NOW + 20,
        jti: nonce.to_string(),
        decision_id: grant.decision_id.clone(),
        challenge: grant.challenge.clone(),
        sandbox_id: grant.intent.sandbox_id.clone(),
        generation: grant.intent.generation.clone(),
        auth_epoch: grant.intent.auth_epoch,
        gateway_token_id: "gateway-jti".into(),
        device_id: grant.device_id.clone(),
        runtime_identity: "kubernetes://ns/uid/pod".into(),
        resource: "provider:credential".into(),
        svid_audience: "token-endpoint".into(),
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.typ = Some("openshell-bootstrap-proof+jwt".into());
    openshell_crypto::jwt::encode(&header, &claims, key).unwrap()
}

async fn provider(
    gate: &BootstrapGate,
    grant: &Grant,
    token: &str,
    spiffe: &str,
    now: i64,
) -> Result<Grant, Denial> {
    gate.provider(
        grant,
        &intent(),
        WorkloadEvidence {
            spiffe_id: spiffe,
            audience: "token-endpoint",
            expires_at: NOW + 100,
            runtime_identity: "kubernetes://ns/uid/pod",
        },
        "gateway-jti",
        token,
        "provider:credential",
        now,
    )
    .await
}

#[tokio::test]
async fn allow_requires_device_workload_sandbox_and_signed_possession() {
    let (gate, store, key) = fixture();
    let grant = gate
        .bootstrap(intent(), "test-device-session", NOW)
        .await
        .unwrap();
    assert!(grant.expires_at <= NOW + 30);
    let permit = provider(
        &gate,
        &grant,
        &proof(&grant, &key, Uuid::new_v4()),
        &intent().expected_spiffe_id,
        NOW,
    )
    .await
    .unwrap();
    assert!(permit.scopes.contains(PROVIDER_CAPABILITY));
    assert!(permit.expires_at <= NOW + 20);
    assert_eq!(store.records.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn explicit_policy_deny_is_audited() {
    let (mut gate, store, _) = fixture();
    gate.authorizer = Arc::new(MockAuthorizer {
        allow: false,
        delay: Duration::ZERO,
    });
    assert_eq!(
        gate.bootstrap(intent(), "test-device-session", NOW).await,
        Err(Denial::PolicyDenied)
    );
    assert!(!store.records.lock().unwrap()[0].allow);
}

#[tokio::test]
async fn audit_or_replay_store_failure_cannot_authorize() {
    let (mut gate, _, key) = fixture();
    let grant = gate
        .bootstrap(intent(), "test-device-session", NOW)
        .await
        .unwrap();
    gate.store = Arc::new(FailingStore { fail_audit: true });
    assert_eq!(
        gate.bootstrap(intent(), "test-device-session", NOW).await,
        Err(Denial::ReplayOrPersistence)
    );
    gate.store = Arc::new(FailingStore { fail_audit: false });
    assert_eq!(
        provider(
            &gate,
            &grant,
            &proof(&grant, &key, Uuid::new_v4()),
            &intent().expected_spiffe_id,
            NOW
        )
        .await,
        Err(Denial::ReplayOrPersistence)
    );
}

#[tokio::test]
async fn missing_signal_and_expired_attestation_fail_closed() {
    let (gate, _, _) = fixture();
    assert_eq!(
        gate.bootstrap(intent(), "", NOW).await,
        Err(Denial::MissingSignal)
    );
    for (missing, lifetime, expected) in [
        (true, 120, Denial::MissingSignal),
        (false, -1, Denial::StaleEvidence),
    ] {
        let (mut gate, store, _) = fixture();
        gate.device = Arc::new(MockDevice {
            public_key: Vec::new(),
            lifetime,
            missing,
        });
        assert_eq!(
            gate.bootstrap(intent(), "test-device-session", NOW).await,
            Err(expected)
        );
        assert!(!store.records.lock().unwrap()[0].allow);
    }
}

#[tokio::test]
async fn wrong_trust_domain_and_spiffe_sandbox_mismatch_fail_closed() {
    let (gate, _, key) = fixture();
    let grant = gate
        .bootstrap(intent(), "test-device-session", NOW)
        .await
        .unwrap();
    for spiffe in [
        "spiffe://evil.org/openshell/gateway/gateway-a/sandbox/sandbox-a",
        "spiffe://example.org/openshell/gateway/gateway-a/sandbox/sandbox-b",
    ] {
        assert_eq!(
            provider(
                &gate,
                &grant,
                &proof(&grant, &key, Uuid::new_v4()),
                spiffe,
                NOW
            )
            .await,
            Err(Denial::IdentityMismatch)
        );
    }
}

#[tokio::test]
async fn authorizer_timeout_fails_closed_and_is_audited() {
    let (mut gate, store, _) = fixture();
    gate.timeout = Duration::from_millis(5);
    gate.authorizer = Arc::new(MockAuthorizer {
        allow: true,
        delay: Duration::from_mins(1),
    });
    assert_eq!(
        gate.bootstrap(intent(), "test-device-session", NOW).await,
        Err(Denial::Timeout)
    );
    assert!(!store.records.lock().unwrap()[0].allow);
}

#[tokio::test]
async fn old_decision_and_consumed_proof_cannot_be_replayed() {
    let (gate, _, key) = fixture();
    let grant = gate
        .bootstrap(intent(), "test-device-session", NOW)
        .await
        .unwrap();
    let token = proof(&grant, &key, Uuid::new_v4());
    provider(&gate, &grant, &token, &intent().expected_spiffe_id, NOW)
        .await
        .unwrap();
    assert_eq!(
        provider(&gate, &grant, &token, &intent().expected_spiffe_id, NOW).await,
        Err(Denial::ReplayOrPersistence)
    );
    assert_eq!(
        provider(
            &gate,
            &grant,
            &token,
            &intent().expected_spiffe_id,
            NOW + 31
        )
        .await,
        Err(Denial::StaleEvidence)
    );
}

#[tokio::test]
async fn stolen_bootstrap_bearer_does_not_enroll_attacker_key() {
    let (gate, store, _) = fixture();
    let grant = gate
        .bootstrap(intent(), "test-device-session", NOW)
        .await
        .unwrap();
    let (_, _, attacker) = fixture();
    assert_eq!(
        provider(
            &gate,
            &grant,
            &proof(&grant, &attacker, Uuid::new_v4()),
            &intent().expected_spiffe_id,
            NOW
        )
        .await,
        Err(Denial::InvalidProof)
    );
    assert_eq!(
        provider(&gate, &grant, "", &intent().expected_spiffe_id, NOW).await,
        Err(Denial::InvalidProof)
    );
    assert_eq!(store.proofs.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn policy_cannot_expand_bootstrap_capabilities() {
    let request = DecisionRequest {
        request_id: Uuid::new_v4().to_string(),
        parent_decision_id: None,
        stage: Stage::Bootstrap,
        intent: intent(),
        device_id: "device".into(),
        device_revision: "v1".into(),
        host_id: None,
        runtime_identity: None,
        spiffe_id: None,
        proof_verified: false,
        selectors: BTreeSet::new(),
        resource: "bootstrap".into(),
        now: NOW,
        expires_at: NOW + 60,
    };
    let response = DecisionResponse {
        allow: true,
        reason: "allow".into(),
        ttl_secs: 60,
        scopes: BTreeSet::from(["provider_access".into()]),
    };
    assert_eq!(
        validate_response(&request, &response, BOOTSTRAP_CAPABILITY),
        Err(Denial::InvalidDecision)
    );
}

#[tokio::test]
#[ignore = "requires pinned OPA; run with OPENSHELL_TEST_OPA and --ignored in CI"]
async fn local_rego_policy_allows_and_denies() {
    let (mut gate, _, key) = fixture();
    gate.authorizer = Arc::new(
        RegoAuthorizer::new(
            std::env::var_os("OPENSHELL_TEST_OPA")
                .expect("OPA path")
                .into(),
        )
        .unwrap(),
    );
    gate.timeout = Duration::from_secs(5);
    let grant = gate
        .bootstrap(intent(), "test-device-session", NOW)
        .await
        .unwrap();
    provider(
        &gate,
        &grant,
        &proof(&grant, &key, Uuid::new_v4()),
        &intent().expected_spiffe_id,
        NOW,
    )
    .await
    .unwrap();
    let mut invalid = intent();
    invalid.owner.clear();
    let invalid_request = DecisionRequest {
        request_id: Uuid::new_v4().to_string(),
        parent_decision_id: None,
        stage: Stage::Bootstrap,
        intent: invalid.clone(),
        device_id: "device-a".into(),
        device_revision: "v1".into(),
        host_id: None,
        runtime_identity: None,
        spiffe_id: None,
        proof_verified: false,
        selectors: BTreeSet::new(),
        resource: BOOTSTRAP_CAPABILITY.into(),
        now: NOW,
        expires_at: NOW + 60,
    };
    let denied = gate.authorizer.decide(&invalid_request).await.unwrap();
    assert!(!denied.allow);
    assert_eq!(denied.reason, "policy_denied");
    let mut docker = intent();
    docker.driver = "docker".into();
    let observation = crate::proto::compute::v1::SupervisorRuntimeObservation {
        sandbox_id: docker.sandbox_id.clone(),
        runtime_identity: format!("docker://{}", "a".repeat(64)),
        generation: docker.generation.clone(),
        auth_epoch: docker.auth_epoch,
    };
    let mut activation = DecisionRequest {
        stage: Stage::Activation,
        spiffe_id: Some(docker_supervisor_spiffe_id(&docker, &observation).unwrap()),
        intent: docker,
        host_id: Some("host-a".into()),
        runtime_identity: Some(observation.runtime_identity),
        proof_verified: true,
        selectors: BTreeSet::from(["verified:fixture".into()]),
        parent_decision_id: Some(grant.decision_id),
        resource: "configuration-fence".into(),
        ..invalid_request
    };
    let allowed = gate.authorizer.decide(&activation).await.unwrap();
    assert_eq!(
        validate_response(&activation, &allowed, ACTIVATION_CAPABILITY),
        Ok(NOW + 30)
    );
    activation.proof_verified = false;
    assert!(!gate.authorizer.decide(&activation).await.unwrap().allow);
    assert!(
        gate.bootstrap(invalid, "test-device-session", NOW)
            .await
            .is_err()
    );
}
