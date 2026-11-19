// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway RPC integration with a mock SPIRE Workload API, broker adapter and
//! Vault HTTP backend. The real Vault credential driver and signed proofs run.

use super::*;
use async_trait::async_trait;
use base64::Engine as _;
use openshell_core::bootstrap_authz::*;
use openshell_core::proto::*;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use openshell_spiffe::{SandboxIdentityProvider, SandboxJwtSvid};
use rcgen::PublicKeyData as _;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, path_regex},
};

#[derive(Clone, prost::Message)]
struct JwtRequest {
    #[prost(string, repeated, tag = "1")]
    audience: Vec<String>,
    #[prost(string, tag = "2")]
    spiffe_id: String,
}
#[derive(Clone, prost::Message)]
struct JwtResponse {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<Jwt>,
}
#[derive(Clone, prost::Message)]
struct Jwt {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(string, tag = "2")]
    svid: String,
}

#[derive(Clone)]
struct MockWorkloadApi(Arc<jsonwebtoken::EncodingKey>);
impl tonic::server::NamedService for MockWorkloadApi {
    const NAME: &'static str = "SpiffeWorkloadAPI";
}
impl tower::Service<http::Request<tonic::body::Body>> for MockWorkloadApi {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let api = self.clone();
        Box::pin(async move {
            struct Fetch(MockWorkloadApi);
            impl tonic::server::UnaryService<JwtRequest> for Fetch {
                type Response = JwtResponse;
                type Future =
                    Pin<Box<dyn Future<Output = Result<Response<JwtResponse>, Status>> + Send>>;
                fn call(&mut self, request: Request<JwtRequest>) -> Self::Future {
                    let key = self.0.0.clone();
                    Box::pin(async move {
                        let req = request.into_inner();
                        let subject = if req.spiffe_id.is_empty() {
                            "spiffe://example.org/gateway".into()
                        } else {
                            req.spiffe_id
                        };
                        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
                        header.kid = Some("fixture".into());
                        let claims = serde_json::json!({"sub": subject, "aud": req.audience, "exp": crate::auth::bootstrap::now() + 120});
                        let svid = openshell_crypto::jwt::encode(&header, &claims, &key).unwrap();
                        Ok(Response::new(JwtResponse {
                            svids: vec![Jwt {
                                spiffe_id: subject,
                                svid,
                            }],
                        }))
                    })
                }
            }
            assert_eq!(request.uri().path(), "/SpiffeWorkloadAPI/FetchJWTSVID");
            let response = tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                .unary(Fetch(api), request)
                .await;
            Ok(response)
        })
    }
}

#[derive(Debug)]
struct MockBrokerAdapter {
    socket: String,
    jwks: Vec<u8>,
}
#[async_trait]
impl SandboxIdentityProvider for MockBrokerAdapter {
    type Error = TokenGrantFailure;
    async fn fetch_jwt_svid(
        &self,
        gateway: &str,
        sandbox: &str,
        audience: &str,
        _: &str,
    ) -> Result<SandboxJwtSvid, Self::Error> {
        let reject = || {
            TokenGrantFailure::new(
                TokenGrantFailureKind::WorkloadIdentityRejected,
                TokenGrantStage::WorkloadIdentity,
            )
        };
        let expected =
            format!("spiffe://example.org/openshell/gateway/{gateway}/sandbox/{sandbox}");
        let id = spiffe::SpiffeId::new(&expected).map_err(|_| reject())?;
        let client = spiffe::WorkloadApiClient::connect_to(format!("unix:{}", self.socket))
            .await
            .map_err(|_| reject())?;
        let token = client
            .fetch_jwt_token([audience], Some(&id))
            .await
            .map_err(|_| reject())?;
        let mut bundles = spiffe::JwtBundleSet::new();
        bundles.add_bundle(
            spiffe::JwtBundle::from_jwt_authorities(
                spiffe::TrustDomain::new("example.org").unwrap(),
                &self.jwks,
            )
            .unwrap(),
        );
        let verified = spiffe::JwtSvid::parse_and_validate(&token, &bundles, &[audience])
            .map_err(|_| reject())?;
        if verified.spiffe_id().to_string() != expected {
            return Err(reject());
        }
        Ok(SandboxJwtSvid {
            spiffe_id: expected,
            expires_at: verified.claims().exp(),
            token,
        })
    }
}

struct MockDevice {
    public_key: Vec<u8>,
    revoked: Arc<AtomicBool>,
}
#[async_trait]
impl DeviceAttestationAdapter for MockDevice {
    async fn attest(&self, context: &AttestationContext) -> Result<DeviceAttestation, Denial> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(Denial::StaleEvidence);
        }
        Ok(DeviceAttestation {
            owner: context.intent.owner.clone(),
            device_id: "device-a".into(),
            host_id: Some("host-a".into()),
            runtime_identity: context.runtime_identity.clone(),
            challenge: context.challenge.clone(),
            compliant: true,
            issued_at: context.now,
            expires_at: context.now + 120,
            device_revision: "enrolled-v1".into(),
            selectors: BTreeSet::from(["test:verified-selector".into()]),
            workload_key_pem: Some(self.public_key.clone()),
        })
    }
}
struct MockSandboxAuthorization;
#[async_trait]
impl SandboxAuthorizationAdapter for MockSandboxAuthorization {
    async fn verify(&self, _: &SandboxIntent, _: i64) -> Result<(), Denial> {
        Ok(())
    }
}
struct AllowPolicy;
#[async_trait]
impl BootstrapAuthorizer for AllowPolicy {
    async fn decide(&self, req: &DecisionRequest) -> Result<DecisionResponse, Denial> {
        Ok(DecisionResponse {
            allow: true,
            reason: "fixture_allowed".into(),
            ttl_secs: 60,
            scopes: BTreeSet::from([match req.stage {
                Stage::Bootstrap => BOOTSTRAP_CAPABILITY,
                Stage::Activation => ACTIVATION_CAPABILITY,
                Stage::Provider => PROVIDER_CAPABILITY,
            }
            .into()]),
        })
    }
}

struct AbortServer(tokio::task::JoinHandle<()>);
impl Drop for AbortServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn bootstrap_docker_configuration_requires_the_live_mtls_supervisor() {
    use crate::auth::bootstrap::{
        ACTIVATION_ANNOTATION, BootstrapRuntime, PersistentDecisionStore,
    };
    use crate::auth::sandbox_jwt::SandboxSessionJwtAuthority;
    use crate::auth::sandbox_session::PersistedSandboxIdentity;
    use crate::compute::NoopTestDriver;
    use crate::multiplex::MultiplexService;
    use compute::v1::SupervisorRuntimeObservation;
    use open_shell_client::OpenShellClient;
    use openshell_crypto::tls::spiffe::SpiffeClientVerifier;
    use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

    let sandbox_id = "sandbox-a";
    let mut identity = PersistedSandboxIdentity::new().unwrap();
    let observation = SupervisorRuntimeObservation {
        sandbox_id: sandbox_id.into(),
        runtime_identity: format!("docker://{}", "a".repeat(64)),
        generation: identity.runtime_generation.as_str().into(),
        auth_epoch: identity.auth_epoch.get(),
    };
    let driver = Arc::new(NoopTestDriver::with_supervisor_observation(
        observation.clone(),
    ));
    let mut state =
        crate::grpc::test_support::test_server_state_with_compute_driver("docker", driver).await;
    let directory = tempfile::tempdir().unwrap();
    let (ca, ca_key) = crate::tls_test_utils::generate_test_certs_with_ca(directory.path());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = SpiffeClientVerifier::new("example.org".into(), roots).unwrap();
    let material = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
    let authority = Arc::new(
        SandboxSessionJwtAuthority::from_pem(
            material.signing_key_pem.as_bytes(),
            material.public_key_pem.as_bytes(),
            material.kid,
            "gateway-a",
            Some(Duration::from_mins(1)),
        )
        .unwrap(),
    );
    authority.require_bootstrap_authorization();
    let revoked = Arc::new(AtomicBool::new(false));
    let gate = BootstrapGate {
        authorizer: Arc::new(AllowPolicy),
        device: Arc::new(MockDevice {
            public_key: Vec::new(),
            revoked: revoked.clone(),
        }),
        sandbox_authorization: Arc::new(MockSandboxAuthorization),
        proof: Arc::new(JwtWorkloadProofVerifier),
        store: Arc::new(PersistentDecisionStore(state.store.clone())),
        timeout: Duration::from_secs(5),
    };
    let runtime = Arc::new(
        BootstrapRuntime::with_test_gate(state.store.clone(), gate)
            .with_test_docker_verifier(verifier),
    );
    let state_mut = Arc::get_mut(&mut state).unwrap();
    state_mut.config.config_delivery_mode = openshell_core::config::ConfigDeliveryMode::Poll;
    state_mut.sandbox_session_jwt_authority = Some(authority.clone());
    state_mut.bootstrap_authorization = Some(runtime.clone());
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: sandbox_id.into(),
            name: sandbox_id.into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(openshell_policy::restrictive_default_policy()),
            ..Default::default()
        }),
        ..Default::default()
    };
    sandbox.set_phase(SandboxPhase::Ready.into());
    let principal = Principal::User(crate::auth::principal::UserPrincipal {
        identity: crate::auth::identity::Identity {
            subject: "user-a".into(),
            display_name: None,
            roles: vec![],
            scopes: vec![],
            provider: crate::auth::identity::IdentityProvider::Oidc,
        },
    });
    let grant = runtime
        .admit(
            &state,
            &principal,
            &sandbox,
            &identity,
            "test-device-session",
        )
        .await
        .unwrap();
    let expected_spiffe = docker_supervisor_spiffe_id(&grant.intent, &observation).unwrap();
    identity.bootstrap = Some(grant.clone());
    identity.write(&mut sandbox.metadata.as_mut().unwrap().annotations);
    state.store.put_message(&sandbox).await.unwrap();
    let launch = authority
        .mint_persisted_launch(sandbox_id, &identity)
        .unwrap();
    let bearer = format!("Bearer {}", launch.supervisor.gateway_token.expose_secret());
    let authenticate = |metadata: &mut tonic::metadata::MetadataMap| {
        metadata.insert("authorization", bearer.parse().unwrap());
    };

    let acceptor = crate::TlsAcceptor::from_files(
        &directory.path().join("server-cert.pem"),
        &directory.path().join("server-key.pem"),
        Some(&directory.path().join("ca.pem")),
        false,
        None,
        None,
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = MultiplexService::new(state.clone());
    let _server = AbortServer(tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            let service = service.clone();
            let acceptor = acceptor.acceptor();
            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await.unwrap();
                let _ = service
                    .serve_tls(stream, crate::auth::audit::ConnectionSource::Peer(peer))
                    .await;
            });
        }
    }));
    let connect = |spiffe: Option<&str>| {
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca.pem()))
            .domain_name("localhost");
        if let Some(id) = spiffe {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = vec![rcgen::SanType::URI(id.try_into().unwrap())];
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let key = openshell_crypto::pki::generate_keypair().unwrap();
            let cert = openshell_crypto::pki::signed_by(params, &key, &ca, &ca_key).unwrap();
            tls = tls.identity(Identity::from_pem(cert.pem(), key.serialize_pem().unwrap()));
        }
        async move {
            OpenShellClient::new(
                Endpoint::from_shared(format!("https://localhost:{}", address.port()))
                    .unwrap()
                    .tls_config(tls)
                    .unwrap()
                    .connect()
                    .await
                    .unwrap(),
            )
        }
    };
    let instance_id = uuid::Uuid::new_v4().to_string();
    let report = |admission| {
        let mut request = Request::new(ReportSandboxConfigurationRequest {
            sandbox_id: sandbox_id.into(),
            admission: Some(admission),
            expected_instance_id: String::new(),
        });
        authenticate(request.metadata_mut());
        request
    };
    let mut bearer_only = connect(None).await;
    bearer_only
        .report_sandbox_configuration(report(SandboxConfigurationAdmission {
            instance_id: instance_id.clone(),
            state: ConfigurationAdmissionState::Pending.into(),
            ..Default::default()
        }))
        .await
        .unwrap();
    let mut request = Request::new(GetSandboxConfigRequest {
        name: sandbox_id.into(),
        workspace_scope: Some(workspace_selector("default")),
    });
    authenticate(request.metadata_mut());
    let config = bearer_only
        .get_sandbox_config(request)
        .await
        .unwrap()
        .into_inner();
    assert!(config.configuration_admitted);
    let accepted = SandboxConfigurationAdmission {
        instance_id,
        state: ConfigurationAdmissionState::Accepted.into(),
        policy_version: config.version,
        policy_hash: config.policy_hash,
        config_revision: config.config_revision,
        provider_env_revision: config.provider_env_revision,
        error: String::new(),
    };
    let wrong_container = expected_spiffe.replace(&"a".repeat(64), &"b".repeat(64));
    let wrong_generation = expected_spiffe.replace(&observation.generation, "old-generation");
    for mut client in [
        bearer_only,
        connect(Some(&wrong_container)).await,
        connect(Some(&wrong_generation)).await,
    ] {
        let error = client
            .report_sandbox_configuration(report(accepted.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied, "{error}");
        let stored = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored
                .metadata
                .unwrap()
                .annotations
                .contains_key(ACTIVATION_ANNOTATION)
        );
        assert_ne!(stored.status.unwrap().configuration_activated, Some(true));
    }

    let mut client = connect(Some(&expected_spiffe)).await;
    revoked.store(true, Ordering::Release);
    assert_eq!(
        client
            .report_sandbox_configuration(report(accepted.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    revoked.store(false, Ordering::Release);
    client
        .report_sandbox_configuration(report(accepted))
        .await
        .unwrap();
    let stored = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status.unwrap().configuration_activated, Some(true));
    let metadata = stored.metadata.unwrap();
    let activation: serde_json::Value =
        serde_json::from_str(&metadata.annotations[ACTIVATION_ANNOTATION]).unwrap();
    assert_eq!(activation["spiffe_id"], expected_spiffe);
    assert_eq!(activation["admission_decision_id"], grant.decision_id);
    assert_eq!(
        activation["decision"]["scopes"],
        serde_json::json!([ACTIVATION_CAPABILITY])
    );
    assert!(activation["decision"]["expires_at"].as_i64().unwrap() <= grant.expires_at);
    let mut request = Request::new(GetSandboxProviderEnvironmentRequest {
        sandbox_id: sandbox_id.into(),
        ..Default::default()
    });
    authenticate(request.metadata_mut());
    let provider = client
        .get_sandbox_provider_environment(request)
        .await
        .unwrap()
        .into_inner();
    assert!(provider.environment.is_empty());
    assert!(provider.dynamic_credentials.is_empty());
    let mut request = Request::new(GetSandboxProviderAccessTokenRequest {
        credential_key: "fixture-key".into(),
    });
    authenticate(request.metadata_mut());
    assert!(
        client
            .get_sandbox_provider_access_token(request)
            .await
            .is_err(),
        "configuration activation must confer no provider access"
    );
}

struct Fixture {
    state: Arc<ServerState>,
    key: String,
    bearer: String,
    grant: Grant,
    signing: jsonwebtoken::EncodingKey,
    revoked: Arc<AtomicBool>,
    vault: MockServer,
    oauth: MockServer,
    _server: AbortServer,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("bootstrap-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = directory.path().join("spire.sock");
        let svid_key = openshell_crypto::pki::generate_keypair().unwrap();
        let public = svid_key.der_bytes();
        let jwks = serde_json::to_vec(
            &serde_json::json!({"keys": [{"kty":"EC", "kid":"fixture", "crv":"P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public[1..33]),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public[33..65])}]}),
        )
        .unwrap();
        let svid_signing =
            jsonwebtoken::EncodingKey::from_ec_pem(svid_key.serialize_pem().unwrap().as_bytes())
                .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(MockWorkloadApi(Arc::new(svid_signing)))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await
                .unwrap();
        });
        let vault = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("^/v1/secret/data/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"data":{"version":1}})),
            )
            .mount(&vault)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("^/v1/secret/data/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"data":{"data":{"value":"fixture-subject-token"}}}),
            ))
            .mount(&vault)
            .await;
        let oauth = MockServer::start().await;
        Mock::given(method("POST")).and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"fixture-upstream-token", "token_type":"Bearer", "expires_in":120}))).mount(&oauth).await;
        let mut state =
            crate::grpc::test_support::test_server_state_with_driver("kubernetes").await;
        let state_mut = Arc::get_mut(&mut state).unwrap();
        let token_file = directory.path().join("vault-token");
        std::fs::write(&token_file, "fixture-vault-token").unwrap();
        let file: crate::config_file::ConfigFile = toml::from_str(&format!(
            "[openshell]\nversion = 2\n[openshell.credential_drivers.vault]\naddress = '{}'\nauth_method = 'token_file'\ntoken_path = '{}'\n", vault.uri(), token_file.display())).unwrap();
        let config = openshell_core::Config::new(None).with_credential_drivers(["vault"]);
        state_mut.credentials = crate::credentials::CredentialRuntime::from_config_file_with_store(
            &config,
            Some(&file),
            state_mut.store.clone(),
        )
        .await
        .unwrap();
        state_mut.config.gateway_jwt = Some(openshell_core::GatewayJwtConfig {
            signing_key_path: std::path::PathBuf::default(),
            public_key_path: std::path::PathBuf::default(),
            kid_path: std::path::PathBuf::default(),
            gateway_id: "gateway-a".into(),
            ttl_secs: std::num::NonZeroU64::new(60),
        });
        state_mut.config.spiffe_broker = Some(openshell_core::config::SpiffeBrokerConfig {
            spiffe_id_prefix: "spiffe://example.org/openshell".into(),
            endpoint: "https://localhost:443".into(),
            node_local_port: None,
            server_spiffe_id: Some("spiffe://example.org/broker".into()),
            server_spiffe_id_prefix: None,
            workload_api_socket_path: socket.display().to_string(),
        });
        state_mut.sandbox_identity = Some(Arc::new(MockBrokerAdapter {
            socket: socket.display().to_string(),
            jwks,
        }));
        let material = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
        let authority = Arc::new(
            crate::auth::sandbox_jwt::SandboxSessionJwtAuthority::from_pem(
                material.signing_key_pem.as_bytes(),
                material.public_key_pem.as_bytes(),
                material.kid,
                "gateway-a",
                Some(Duration::from_mins(1)),
            )
            .unwrap(),
        );
        authority.require_bootstrap_authorization();
        state_mut.sandbox_session_jwt_authority = Some(authority.clone());
        let workload_key = openshell_crypto::pki::generate_jwt_keypair().unwrap();
        let signing = jsonwebtoken::EncodingKey::from_ed_pem(
            workload_key.serialize_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let revoked = Arc::new(AtomicBool::new(false));
        let gate = BootstrapGate {
            authorizer: Arc::new(AllowPolicy),
            device: Arc::new(MockDevice {
                public_key: workload_key.public_key_pem().into_bytes(),
                revoked: revoked.clone(),
            }),
            sandbox_authorization: Arc::new(MockSandboxAuthorization),
            proof: Arc::new(JwtWorkloadProofVerifier),
            store: Arc::new(crate::auth::bootstrap::PersistentDecisionStore(
                state_mut.store.clone(),
            )),
            timeout: Duration::from_secs(5),
        };
        let runtime = Arc::new(crate::auth::bootstrap::BootstrapRuntime::with_test_gate(
            state_mut.store.clone(),
            gate,
        ));
        state_mut.bootstrap_authorization = Some(runtime.clone());
        let profile = ProviderProfile {
            category: ProviderProfileCategory::Other.into(),
            id: "bootstrap-fixture".into(),
            display_name: "Bootstrap fixture".into(),
            credentials: vec![
                ProviderProfileCredential {
                    name: "subject_token".into(),
                    required: true,
                    ..Default::default()
                },
                ProviderProfileCredential {
                    name: "access_token".into(),
                    auth_style: "bearer".into(),
                    header_name: "Authorization".into(),
                    token_grant: Some(ProviderCredentialTokenGrant {
                        grant_type: ProviderCredentialTokenGrantType::TokenExchange.into(),
                        token_endpoint: format!("{}/token", oauth.uri()),
                        jwt_svid_audience: "fixture-token-service".into(),
                        audience: "https://api.example.org".into(),
                        scopes: vec!["read".into()],
                        subject_token: Some(ProviderCredentialTokenGrantSubjectToken {
                            source: "provider_credential".into(),
                            credential: "subject_token".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            endpoints: vec![NetworkEndpoint {
                host: "api.example.org".into(),
                port: 443,
                protocol: "rest".into(),
                access: NetworkAccessPreset::ReadOnly.into(),
                enforcement: NetworkEnforcementMode::Enforce.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        state
            .store
            .put_message(&crate::provider_profile_sources::stored_provider_profile(
                profile.clone(),
            ))
            .await
            .unwrap();
        let mut provider = Provider {
            metadata: Some(ObjectMeta {
                id: "provider-id".into(),
                name: "provider-a".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            r#type: profile.id.clone(),
            ..Default::default()
        };
        provider.credential_handles = state
            .credentials
            .store_provider_credentials(
                "provider-a",
                "default",
                "provider-id",
                &HashMap::from([("subject_token".into(), "fixture-subject-token".into())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        state.store.put_message(&provider).await.unwrap();
        let mut dynamic = HashMap::new();
        insert_dynamic_credentials_for_profile(
            &mut dynamic,
            &openshell_providers::ProviderTypeProfile::from_proto(&profile),
            "provider-a",
            "provider-id",
        )
        .unwrap();
        let key = dynamic.into_keys().next().unwrap();
        let mut identity = crate::auth::sandbox_session::PersistedSandboxIdentity::new().unwrap();
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox-a".into(),
                name: "sandbox-a".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                providers: vec!["provider-a".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready.into());
        let principal = Principal::User(crate::auth::principal::UserPrincipal {
            identity: crate::auth::identity::Identity {
                subject: "user-a".into(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: crate::auth::identity::IdentityProvider::Oidc,
            },
        });
        let grant = runtime
            .admit(
                &state,
                &principal,
                &sandbox,
                &identity,
                "test-device-session",
            )
            .await
            .unwrap();
        identity.bootstrap = Some(grant.clone());
        let annotations = &mut sandbox.metadata.as_mut().unwrap().annotations;
        identity.write(annotations);
        annotations.insert(
            crate::compute::COMPUTE_DRIVER_ANNOTATION.into(),
            "kubernetes".into(),
        );
        annotations.insert(
            crate::compute::COMPUTE_RUNTIME_IDENTITY_ANNOTATION.into(),
            "kubernetes://default/runtime/pod".into(),
        );
        state.store.put_message(&sandbox).await.unwrap();
        let bearer = authority
            .mint_persisted_launch("sandbox-a", &identity)
            .unwrap()
            .supervisor
            .gateway_token
            .expose_secret()
            .to_owned();
        Self {
            state,
            key,
            bearer,
            grant,
            signing,
            revoked,
            vault,
            oauth,
            _server: AbortServer(server),
            _directory: directory,
        }
    }

    fn request(
        &self,
        sign_with: Option<&jsonwebtoken::EncodingKey>,
    ) -> Request<GetSandboxProviderAccessTokenRequest> {
        let session = self
            .state
            .sandbox_session_jwt_authority
            .as_ref()
            .unwrap()
            .verify_gateway_token(&self.bearer)
            .unwrap();
        let mut request = Request::new(GetSandboxProviderAccessTokenRequest {
            credential_key: self.key.clone(),
        });
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.bearer).parse().unwrap(),
        );
        request.extensions_mut().insert(Principal::Sandbox(
            crate::auth::principal::SandboxPrincipal {
                sandbox_id: "sandbox-a".into(),
                source: crate::auth::principal::SandboxIdentitySource::BootstrapJwt {
                    issuer: "launch-session".into(),
                    auth_epoch: Some(session.auth_epoch),
                },
                trust_domain: None,
            },
        ));
        if let Some(key) = sign_with {
            let now = crate::auth::bootstrap::now();
            let claims = ProofClaims {
                iss: "openshell-workload-proof".into(),
                sub: self.grant.intent.expected_spiffe_id.clone(),
                aud: "gateway-a".into(),
                iat: now,
                exp: now + 20,
                jti: uuid::Uuid::new_v4().to_string(),
                decision_id: self.grant.decision_id.clone(),
                challenge: self.grant.challenge.clone(),
                sandbox_id: "sandbox-a".into(),
                generation: self.grant.intent.generation.clone(),
                auth_epoch: self.grant.intent.auth_epoch,
                gateway_token_id: session.token_id.to_string(),
                device_id: "device-a".into(),
                runtime_identity: "kubernetes://default/runtime/pod".into(),
                resource: self.key.clone(),
                svid_audience: "fixture-token-service".into(),
            };
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
            header.typ = Some("openshell-bootstrap-proof+jwt".into());
            let proof = openshell_crypto::jwt::encode(&header, &claims, key).unwrap();
            request
                .metadata_mut()
                .insert(crate::auth::bootstrap::PROOF_HEADER, proof.parse().unwrap());
        }
        request
    }

    async fn vault_reads(&self) -> usize {
        self.vault
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "GET")
            .count()
    }
}

#[tokio::test]
async fn bootstrap_gate_protects_real_vault_resolution_and_oauth_with_mock_workload_api() {
    let fixture = Fixture::new().await;
    let key = openshell_crypto::pki::generate_jwt_keypair().unwrap();
    let attacker =
        jsonwebtoken::EncodingKey::from_ed_pem(key.serialize_pem().unwrap().as_bytes()).unwrap();
    for request in [fixture.request(None), fixture.request(Some(&attacker))] {
        assert!(handle(&fixture.state, request).await.is_err());
        assert_eq!(fixture.vault_reads().await, 0);
        assert!(fixture.oauth.received_requests().await.unwrap().is_empty());
    }
    // A profile snapshot read before Gate 2 must match the admitted snapshot,
    // even if the gateway's current profile has since reverted to the approved one.
    let mut stale = grant_configuration(&fixture.state, "sandbox-a", &fixture.key)
        .await
        .unwrap();
    stale.grant.scopes.push("unapproved-scope".into());
    let session = fixture
        .state
        .sandbox_session_jwt_authority
        .as_ref()
        .unwrap()
        .verify_gateway_token(&fixture.bearer)
        .unwrap();
    let request = fixture.request(Some(&fixture.signing));
    let proof = request
        .metadata()
        .get(crate::auth::bootstrap::PROOF_HEADER)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        fixture
            .state
            .bootstrap_authorization
            .as_ref()
            .unwrap()
            .provider_permit(
                &fixture.state,
                &session,
                proof,
                &stale.key,
                "fixture-token-service",
                (&stale.provider, &stale.grant)
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.vault_reads().await, 0);
    assert!(fixture.oauth.received_requests().await.unwrap().is_empty());
    let request = fixture.request(Some(&fixture.signing));
    let mut concurrent = fixture.request(Some(&fixture.signing));
    let replay_metadata = request.metadata().clone();
    *concurrent.metadata_mut() = replay_metadata.clone();
    let (first, second) = tokio::join!(
        handle(&fixture.state, request),
        handle(&fixture.state, concurrent)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let response = first.or(second).unwrap().into_inner();
    assert_eq!(response.access_token, "fixture-upstream-token");
    assert!(fixture.vault_reads().await > 0);
    let reads = fixture.vault_reads().await;
    let exchanges = fixture.oauth.received_requests().await.unwrap().len();
    assert_eq!(exchanges, 2);
    let mut replay = fixture.request(Some(&fixture.signing));
    *replay.metadata_mut() = replay_metadata;
    assert!(handle(&fixture.state, replay).await.is_err());
    assert_eq!(fixture.vault_reads().await, reads);
    assert_eq!(
        fixture.oauth.received_requests().await.unwrap().len(),
        exchanges
    );
    fixture.revoked.store(true, Ordering::Release);
    assert!(
        handle(&fixture.state, fixture.request(Some(&fixture.signing)))
            .await
            .is_err()
    );
    assert_eq!(fixture.vault_reads().await, reads);
    assert_eq!(
        fixture.oauth.received_requests().await.unwrap().len(),
        exchanges
    );
    fixture
        .state
        .bootstrap_authorization
        .as_ref()
        .unwrap()
        .revoke(&fixture.grant.decision_id)
        .await
        .unwrap();
    assert!(
        fixture
            .state
            .bootstrap_authorization
            .as_ref()
            .unwrap()
            .verify_grant(&fixture.grant)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bootstrap_gate_denies_a_runtime_recorded_for_another_driver() {
    let fixture = Fixture::new().await;
    let mut sandbox = fixture
        .state
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    sandbox.metadata.as_mut().unwrap().annotations.insert(
        crate::compute::COMPUTE_DRIVER_ANNOTATION.into(),
        "docker".into(),
    );
    fixture.state.store.put_message(&sandbox).await.unwrap();

    let response = handle(&fixture.state, fixture.request(Some(&fixture.signing))).await;
    assert!(response.is_err());
    assert_eq!(fixture.vault_reads().await, 0);
    assert!(fixture.oauth.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn bootstrap_revocation_denies_new_supervisor_control_requests() {
    use crate::auth::authenticator::{Authentication, Authenticator as _};
    use crate::auth::sandbox_jwt::SandboxSessionJwtAuthenticator;

    let fixture = Fixture::new().await;
    let authenticator = SandboxSessionJwtAuthenticator::new(
        fixture
            .state
            .sandbox_session_jwt_authority
            .as_ref()
            .unwrap()
            .clone(),
        fixture.state.store.clone(),
    );
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {}", fixture.bearer).parse().unwrap(),
    );
    let method = "/openshell.v1.OpenShell/ConnectSupervisor";
    assert!(matches!(
        authenticator.authenticate(&headers, method).await.unwrap(),
        Authentication::Accepted(_)
    ));
    fixture
        .state
        .bootstrap_authorization
        .as_ref()
        .unwrap()
        .revoke(&fixture.grant.decision_id)
        .await
        .unwrap();
    let rejection = authenticator
        .authenticate(&headers, method)
        .await
        .unwrap_err();
    assert_eq!(rejection.status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn bootstrap_gate_denies_create_before_runtime_or_launch_credentials() {
    use openshell_core::proto::open_shell_server::OpenShell as _;
    let mut fixture = Fixture::new().await;
    let state = Arc::get_mut(&mut fixture.state).unwrap();
    let runtime = Arc::get_mut(state.bootstrap_authorization.as_mut().unwrap()).unwrap();
    runtime.gate.device = Arc::new(UnavailableDeviceAttestation);
    let mut request = Request::new(CreateSandboxRequest {
        name: "denied-bootstrap".into(),
        workspace_scope: Some(workspace_selector("default")),
        spec: Some(SandboxSpec {
            template: Some(SandboxTemplate {
                image: "ubuntu:24.04".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    request.metadata_mut().insert(
        crate::auth::bootstrap::DEVICE_HEADER,
        "fixture-device-session".parse().unwrap(),
    );
    request
        .extensions_mut()
        .insert(Principal::User(crate::auth::principal::UserPrincipal {
            identity: crate::auth::identity::Identity {
                subject: "user-a".into(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: crate::auth::identity::IdentityProvider::Oidc,
            },
        }));
    let service = crate::grpc::OpenShellService::new(fixture.state.clone());
    let error = service.create_sandbox(request).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied, "{error}");
    assert!(error.message().contains("bootstrap"), "{error}");
    assert!(
        fixture
            .state
            .store
            .get_message_by_name::<Sandbox>("default", "denied-bootstrap")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.vault_reads().await, 0);
}

#[tokio::test]
async fn bootstrap_gate_rejects_legacy_exchange_and_snapshots_without_secret_reads() {
    let fixture = Fixture::new().await;
    let sandbox = fixture
        .state
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    assert!(
        crate::grpc::policy::build_provider_environment_snapshot(
            &fixture.state,
            &sandbox,
            true,
            true
        )
        .await
        .is_err()
    );
    assert_eq!(fixture.vault_reads().await, 0);
    assert!(fixture.oauth.received_requests().await.unwrap().is_empty());
}
