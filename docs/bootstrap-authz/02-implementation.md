---
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
title: "Bootstrap authorization implementation notes"
description: "Implemented enforcement, test boundaries and remaining production integrations."
---

## Implemented slice

Verified implementation: the runtime flag is `[openshell.gateway.bootstrap_authorization] enabled = true`, default off. The gateway composes `BootstrapAuthorizer`, device/host attestation, sandbox authorization, workload-key proof verification and durable decision storage. Local OPA evaluates the bundled Rego policy through a bounded subprocess; it receives verified attributes rather than raw JWTs or keys. See [the engine](../../crates/openshell-core/src/bootstrap_authz.rs), [the policy](../../crates/openshell-core/src/bootstrap_authz/policy.rego), and [gateway enforcement](../../crates/openshell-server/src/auth/bootstrap.rs).

Verified implementation: Gate 1 runs in `handle_create_sandbox_inner` before session JWT minting. It binds the authenticated owner, workspace, canonical sandbox/effective policy/provider-profile digest, configured driver, sandbox ID, runtime generation, expected SPIFFE identity and verified requester device. The grant is written to a gateway-owned store and carried in both typed JWT profiles. The token expiry cannot exceed the decision, and bootstrap tokens have a restricted method allowlist. See [sandbox creation](../../crates/openshell-server/src/grpc/sandbox.rs), [JWT minting/verification](../../crates/openshell-core/src/jwt.rs), and [gateway session enforcement](../../crates/openshell-server/src/auth/sandbox_jwt.rs).

Verified implementation: Gate 2 protects `GetSandboxProviderAccessToken` before stored subject-token resolution, provider-token cache access, or OAuth grants. It obtains a verified sandbox SVID through the existing identity adapter, matches the exact expected SPIFFE ID and recorded runtime identity, revalidates owner/policy permission and device/host evidence, requires verified selector facts, and verifies a caller-held workload key. Rechecks before outbound grants and delivery reject changed evidence, policy/profile inputs, runtime, generation, epoch, token lineage, or revoked grant. See [`obtain` and `acquire`](../../crates/openshell-server/src/grpc/provider/access_token.rs).

Verified implementation. Each provider operation requires a single-use, resource-bound Gate 2 permit. Enabled mode bypasses token caches and rejects extension issuance, legacy intermediate exchanges, and credential-bearing configuration snapshots, including cached snapshots. A new generation or takeover term requires fresh admission before the bootstrap-required signing authority can mint credentials.

Verified implementation. Shared Kubernetes supervisors renew the gateway and Sandbox Protocol JWTs through the existing `RefreshSandboxToken` RPC. Renewal requires a single-use workload proof for that RPC and a dedicated internal SVID audience. The gateway rechecks device and host posture, independent key enrollment, current runtime, and owner and policy authorization. The renewed JWTs carry a fresh bootstrap-only decision and challenge. Their expiry is capped by the current policy, attestation, SVID, and proof. A compare-and-set installs the successor for the same sandbox generation and credential epoch. The bounded recovery path requires a new proof using the still-valid previous JWT and returns the committed successor. Revoking the original admission invalidates all renewed gateway sessions. The Sandbox Protocol token's verifier enforces its signed expiry locally. [Refresh handler](../../crates/openshell-server/src/grpc/auth_rpc.rs), [renewal policy](../../crates/openshell-core/src/bootstrap_authz/policy.rego), [lineage persistence](../../crates/openshell-server/src/auth/sandbox_session.rs).

Verified implementation: immutable decision records and proof receipts use the existing durable object store. Proof receipt creation is atomic across replicas. Every core gate evaluation requires durable allow/deny recording before returning permission and emits structured fields without credentials. Persistence failure denies and still emits an independent denial log. Grant revocation removes the stored grant, which subsequent enforcement rereads. Independent administrative provider storage/refresh remains outside sandbox admission.

## Proof protocol

Verified implementation: admission accepts exactly one `x-openshell-device-evidence` header with opaque device evidence or an attestation-session reference. The trusted adapter must independently bind the claimant, authenticated owner, sandbox intent and fresh gateway challenge. An enrolled-device lookup by owner alone does not prove possession. The evidence is not sent to OPA or recorded in audit logs. See [`AttestationContext`](../../crates/openshell-core/src/bootstrap_authz.rs) and [request handling](../../crates/openshell-server/src/grpc/sandbox.rs).

Verified implementation. Protected provider and renewal requests require exactly one `x-openshell-workload-proof` header containing an Ed25519 JWT of type `openshell-bootstrap-proof+jwt`. The trusted attestation adapter supplies the enrolled public key, independently bound to the runtime and host identity. See [`ProofClaims` and `JwtWorkloadProofVerifier`](../../crates/openshell-core/src/bootstrap_authz.rs).

Verified implementation. The signed proof contains issuer `openshell-workload-proof`, subject equal to the exact workload SPIFFE ID, audience equal to the gateway ID, a unique UUID `jti`, `iat` and `exp`, admission decision ID, gateway-generated admission challenge, sandbox ID, runtime generation, credential epoch, gateway token JTI, device ID, immutable runtime reference, operation resource, and SVID audience. The resource names the configured credential key for provider requests and the RPC path for renewal. Proofs must be issued within the previous 30 seconds and expire within 30 seconds. The gateway consumes each nonce once across replicas and applies no clock leeway to proof expiry.

Verified implementation: per-request permits stop reusable-bearer promotion from weakening the proof requirement. Already-exported upstream tokens remain bearer credentials with issuer-controlled lifetimes. Capping the gateway response/serving lifetime does not shorten the upstream token's cryptographic lifetime or revoke it after export. Operators still need upstream revocation, short issuer TTLs, or sender-constrained upstream credentials.

Unverified threat analysis: a thief who captures both the bootstrap bearer and a valid, unconsumed signed proof can race the intended request. Atomic consumption guarantees at most one success, not which connection wins. Required gateway TLS protects transport confidentiality; the signed proof has no TLS-channel binding. Protecting against full-request theft requires a separately reviewed channel binding or encrypted credential delivery. The stolen-bearer test establishes protection only when the thief lacks a valid proof and the enrolled key.

## Stubs and deployment limits

Verified implementation. The default adapters deny. With `posture_authority` configured, the gateway uses mTLS to query an operator-run evidence verifier and rechecks the owner's explicit workspace membership and active workspace state. Canonical sandbox, policy and provider configuration remain bound by the grant's digest. The workspace adapter supports owner authorization. Mission authorization and workload key enrollment are separate integrations. [Authority adapters](../../crates/openshell-server/src/auth/bootstrap/authority.rs).

Verified implementation. Kubernetes bootstrap configuration delivers metadata for dynamic provider token grants without resolving provider values or files. Push reconciliation bypasses previously resolved environment snapshots while bootstrap authorization is enabled. [Snapshot builder](../../crates/openshell-server/src/grpc/policy.rs), [Push reconciliation](../../crates/openshell-server/src/config_delivery/mod.rs).

### Posture authority contract

Verified implementation. The gateway sends an HTTPS POST to the configured endpoint. The service must require a gateway client certificate. The JSON request contains `stage`, `challenge`, `intent`, `runtime_identity`, `expected_device_id`, and `request_evidence`. The `bootstrap` stage sends the requester evidence reference. The `provider` and `renewal` stages require current host and device posture and the independently enrolled workload key for the recorded runtime. Workload proofs stay on the gateway.

For verified evidence, return HTTP 200 with `owner`, `device_id`, `device_revision`, `challenge`, `issued_at`, `expires_at`, `compliant`, `host_id`, `runtime_identity`, `selectors`, and `workload_key_pem`. Use Unix seconds for timestamps and nullable fields for unavailable host, runtime, or key evidence. The gateway validates the returned challenge and freshness. Return HTTP 403 when verification denies. Connection errors, oversized responses, malformed responses, and missing required evidence fail closed. [Authority adapter](../../crates/openshell-server/src/auth/bootstrap/authority.rs), [Gate checks](../../crates/openshell-core/src/bootstrap_authz.rs).

Unverified deployment requirements. The authority must independently bind requester possession, the authenticated owner and the canonical launch intent using a challenge-bound evidence session. At the later gates it must reverify current host posture and, for Kubernetes provider grants, the public key enrolled for the exact runtime generation. A response obtained by looking up the named owner or echoing caller-provided selectors does not establish those facts. Configure a real authority and an enrollment path before qualification.

Verified implementation. The shared Kubernetes supervisor selects an operator-provisioned key file by sandbox, generation and credential epoch. It verifies the current gateway JWT with enrolled gateway verification keys and signs the resource, SVID audience, and bearer ID for the request. The gateway independently verifies the workload key and current runtime. Missing or invalid key material denies credential access. [Signer](../../crates/openshell-core/src/bootstrap_signer.rs), [gateway client](../../crates/openshell-core/src/grpc_client.rs).

Unverified integration requirements. Deploy a real requester and host attestation authority, automate independent workload key enrollment, and verify SPIRE selector and registration provenance against a live cluster. VAAS can implement the authorizer interface later.

Verified implementation. Both modes require gateway TLS and positive session TTLs. Kubernetes uses gateway supervision and the SPIFFE broker. Docker and Podman check an X.509-SVID and a live container observation at polling configuration admission. Their decisions authorize configuration activation only. See the [Docker](03-lifecycle-integration.md#docker-spire-prototype) and [Podman](03-lifecycle-integration.md#podman-spiffe-activation) integrations. Unverified deployment requirement. Use the same flag and policy on every replica sharing a gateway signing identity. The gateway flag cannot revoke credentials or sockets already distributed outside its configuration.

Verified boundary: Gate 2 guards provider credentials. Launch still prepares SSH identity and applies configured OTLP authentication headers/client TLS before Gate 2; see [`prepare_ssh_identity` and `encode_launch_authentication`](../../crates/openshell-server/src/compute/mod.rs). These are bootstrap infrastructure exceptions. Unverified deployment assumption: operators constrain their destinations and privileges. This slice does not establish workload/host attestation before those infrastructure credentials exist, nor resolve the design's open question about deferring them.

Unverified follow-up work. Proof-capable static-secret delivery, local runtime renewal, runtime ownership changes with fresh admission, and real SPIRE Broker transport need live qualification. Frequent renewal adds durable decision and proof records. Set retention only after preserving launch records for the life of their lineages and determining safe expiry for proofs and audit records.

## Validation boundaries

Verified test coverage in source: core tests cover allow/deny, missing/expired attestation, wrong trust domain and exact sandbox identity, authorizer timeout, audit/replay persistence failure, scope expansion, old decisions, proof replay and a stolen bootstrap bearer signing with an attacker key. JWT tests check both profile TTL caps and absence of the new claim in legacy serialization. See [core tests](../../crates/openshell-core/src/bootstrap_authz/tests.rs) and [JWT tests](../../crates/openshell-core/src/jwt.rs).

Verified test fixture. The gateway RPC integration uses a mock SPIRE Workload API over a Unix socket, a mock broker adapter that validates its SVID, the real Vault credential driver against a mock Vault HTTP backend, and a mock OAuth endpoint. It checks that denied requests cause zero additional Vault reads or exchanges. The production provider client also exercises the signer over TLS with a provisioned test key. Live SPIRE Broker transport and real host enrollment require separate qualification. [Integration fixture](../../crates/openshell-server/src/grpc/provider/access_token/bootstrap_tests.rs).

Verified CI result for the initial slice at `fe853cdc`: [Bootstrap authorization run 44524632575](https://github.com/lpassig/vault-openshell/actions/runs/44524632575) passed formatting, core authorization with pinned OPA, gateway SPIRE/Vault/OAuth integration and existing authentication regressions.

The [lifecycle integration design](03-lifecycle-integration.md) maps upstream configuration admission, native runtime binding and the backend protocol to the remaining cross-runtime credential activation work.

## Suggested PR description

Add opt-in bootstrap authorization before sandbox launch JWT issuance and before gateway-owned Kubernetes provider-token acquisition. Bind Docker and Podman polling configuration admission to a live container observation and the supervisor's SPIFFE mTLS connection. Revalidate device, host, and sandbox authorization for each protected operation.

The default adapters deny until a real verifier and authorization authority are integrated. Tests exercise shared-supervisor proof signing, bootstrap JWT renewal, local OPA, Docker and Podman configuration admission, mock SPIRE identity, and Vault/OAuth access ordering. Production enrollment, local runtime renewal, and local provider delivery remain open.

| Threat | Mitigation in this slice | Residual risk |
| --- | --- | --- |
| Stolen bootstrap JWT | Independently attested workload key and context-bound signed proof before provider access. | Compromised verifier or legitimate workload key defeats this boundary. |
| Captured bearer and unconsumed proof | Gateway TLS, narrow request binding, short proof expiry and atomic consumption. | A thief can win the first-use race; TLS-channel binding or encrypted delivery is not implemented. |
| Replayed proof or expired decision | Atomic persistent proof receipts, short proof/decision expiry, current grant lookup. | Receipt/audit retention and production scaling need qualification. |
| Renewal using a copied JWT | Require fresh workload proof and re-attestation for rotation and recovery, then check durable launch revocation. | Local Sandbox Protocol credentials expire according to their signed TTL. |
| Same-domain SVID for another sandbox | Exact configured SPIFFE mapping, sandbox/runtime/generation/epoch binding. | Incorrect or compromised SPIRE registrations remain a trust-root risk. |
| Copied local launch JWT | Require same-connection SPIFFE mTLS and a current driver observation before accepting configuration. Podman identities use their own path segment. | Trusted registration and runtime isolation determine who can use the supervisor key. |
| Vault or cache bypass | Gate before subject resolution, cache bypass, denial of unguarded snapshot and legacy exchange paths. | Independent administrator exports and external grant paths require separate control. |
| Revocation during asynchronous work | Current authorization/evidence/runtime rechecks before grants and delivery. | Rechecks and external issuance are not atomic; already-exported credentials require issuer-side revocation or expiry. |
| Mixed replica configuration | Require consistent flag, policy and adapter configuration across replicas. | A disabled replica sharing signing keys can bypass admission; deployment enforcement remains an integration requirement. |
