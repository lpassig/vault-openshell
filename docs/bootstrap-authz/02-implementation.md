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

Verified implementation: this slice issues a single-use, resource-bound Gate 2 permit for each provider operation. It does not promote the bootstrap JWT into a reusable provider-capable bearer. Enabled mode bypasses token caches, rejects session renewal and extension issuance, and rejects legacy intermediate exchanges and credential-bearing configuration snapshots, including cached snapshots. New generations or takeover terms without fresh admission cannot mint credentials through a bootstrap-required signing authority. These restrictions narrow the implementation relative to the broader design; they preserve denial until each additional path can verify key possession.

Verified implementation: immutable decision records and proof receipts use the existing durable object store. Proof receipt creation is atomic across replicas. Every core gate evaluation requires durable allow/deny recording before returning permission and emits structured fields without credentials. Persistence failure denies and still emits an independent denial log. Grant revocation removes the stored grant, which subsequent enforcement rereads. Independent administrative provider storage/refresh remains outside sandbox admission.

## Proof protocol

Verified implementation: admission accepts exactly one `x-openshell-device-evidence` header with opaque device evidence or an attestation-session reference. The trusted adapter must independently bind the claimant, authenticated owner, sandbox intent and fresh gateway challenge. An enrolled-device lookup by owner alone does not prove possession. The evidence is not sent to OPA or recorded in audit logs. See [`AttestationContext`](../../crates/openshell-core/src/bootstrap_authz.rs) and [request handling](../../crates/openshell-server/src/grpc/sandbox.rs).

Verified implementation: callers of the protected RPC must supply exactly one `x-openshell-workload-proof` header containing an Ed25519 JWT of type `openshell-bootstrap-proof+jwt`. The trusted attestation adapter supplies the enrolled public key, independently bound to runtime/host identity. The bootstrap bearer cannot enroll or substitute that key. See [`ProofClaims` and `JwtWorkloadProofVerifier`](../../crates/openshell-core/src/bootstrap_authz.rs).

Verified implementation: the signed proof contains issuer `openshell-workload-proof`, subject equal to the exact workload SPIFFE ID, audience equal to the gateway ID, a unique UUID `jti`, `iat` and `exp`, admission decision ID, gateway-generated admission challenge, sandbox ID, runtime generation, credential epoch, current gateway token JTI, device ID, immutable runtime reference, exact configured credential key and SVID audience. Proofs must be issued within the previous 30 seconds, expire within 30 seconds, and be unexpired without clock leeway. The admission challenge is bound to the short-lived session; each signed proof nonce is consumed once, including across replicas. This is request proof of possession, not a new public challenge RPC.

Verified implementation: per-request permits stop reusable-bearer promotion from weakening the proof requirement. Already-exported upstream tokens remain bearer credentials with issuer-controlled lifetimes. Capping the gateway response/serving lifetime does not shorten the upstream token's cryptographic lifetime or revoke it after export. Operators still need upstream revocation, short issuer TTLs, or sender-constrained upstream credentials.

## Stubs and deployment limits

Verified implementation: the shipped `UnavailableDeviceAttestation` and `UnavailableSandboxAuthorization` adapters deny. Mocks exist only in tests. The CLI has no production enrollment, device-posture service, owner/mission authority connector, or supervisor proof signer. Enabling this flag with the shipped adapters therefore prevents admission; it does not silently trust request labels, service-account tokens, or a matching SVID.

Unverified integration requirements: select and implement real requester/host attestation and owner/mission authorities, independently enroll workload keys, and verify SPIRE selector/registration provenance. Gateway embedding integrations can replace the adapter interfaces; a deployable provider bridge and supervisor signer are additional work. VAAS can implement the authorizer interface later and is not assumed by this implementation.

Verified implementation: CLI activation requires gateway TLS, Kubernetes gateway supervision, positive session TTLs, a SPIFFE broker, and no configured supervisor Workload API socket. Unverified deployment requirement: every replica sharing a gateway signing identity must enforce the same flag and policy; mixed enabled/disabled replicas allow a downgrade through the disabled replica. Operators must also prevent alternate Workload API access and authorization-server grant policies from bypassing gateway mediation. The gateway flag cannot revoke credentials or sockets already distributed outside its configuration.

Unverified follow-up work: proof-capable static-secret/configuration delivery, renewable sessions, runtime ownership changes with fresh admission, audit/proof receipt retention, real SPIRE Broker API transport integration tests, and deployment qualification. Decision and replay records are retained in this slice; production storage growth and retention require review. No claim of production readiness follows from mock-backed tests.

## Validation boundaries

Verified test coverage in source: core tests cover allow/deny, missing/expired attestation, wrong trust domain and exact sandbox identity, authorizer timeout, audit/replay persistence failure, scope expansion, old decisions, proof replay and a stolen bootstrap bearer signing with an attacker key. JWT tests check both profile TTL caps and absence of the new claim in legacy serialization. See [core tests](../../crates/openshell-core/src/bootstrap_authz/tests.rs) and [JWT tests](../../crates/openshell-core/src/jwt.rs).

Verified test fixture: the gateway RPC integration uses an actual mock SPIRE Workload API over a Unix socket, a mock broker adapter that cryptographically validates its SVID, the real Vault credential driver against a mock Vault HTTP backend, and a mock OAuth endpoint. It checks that missing/wrong/replayed proofs and revoked posture cause zero additional Vault reads or OAuth exchanges. The broker's real X.509/mTLS transport is outside this fixture; this test does not qualify a SPIRE deployment. See [the integration fixture](../../crates/openshell-server/src/grpc/provider/access_token/bootstrap_tests.rs).

Verified CI definition: [Bootstrap authorization](../../.github/workflows/bootstrap-authz.yml) pins OPA 1.22.4 with its binary checksum, runs the real Rego evaluator, and runs the core and gateway authentication/security tests. A workflow definition is not evidence of a successful run; execution results must be reported separately.

## Suggested PR description

Add opt-in bootstrap authorization before sandbox launch JWT issuance and before gateway-owned provider-token acquisition. Preserve legacy behavior by default. Require independently verified device/host and sandbox authorization plus a signed, single-use workload proof; deny unsupported credential paths while enabled.

The default adapters deny until a real verifier and authorization authority are integrated. Tests exercise signed proofs, local OPA, gateway enforcement, mock SPIRE identity and Vault/OAuth access ordering. This slice is intended for integration and review, with production enrollment, signing, renewal and static-secret delivery still deferred.

| Threat | Mitigation in this slice | Residual risk |
| --- | --- | --- |
| Stolen bootstrap JWT | Independently attested workload key and context-bound signed proof before provider access. | Compromised verifier or legitimate workload key defeats this boundary. |
| Replayed proof or expired decision | Atomic persistent proof receipts, short proof/decision expiry, current grant lookup. | Receipt/audit retention and production scaling need qualification. |
| Same-domain SVID for another sandbox | Exact configured SPIFFE mapping, sandbox/runtime/generation/epoch binding. | Incorrect or compromised SPIRE registrations remain a trust-root risk. |
| Vault or cache bypass | Gate before subject resolution, cache bypass, denial of unguarded snapshot and legacy exchange paths. | Independent administrator exports and external grant paths require separate control. |
| Revocation during asynchronous work | Current authorization/evidence/runtime rechecks before grants and delivery. | Rechecks and external issuance are not atomic; already-exported credentials require issuer-side revocation or expiry. |
| Mixed replica configuration | Require consistent flag, policy and adapter configuration across replicas. | A disabled replica sharing signing keys can bypass admission; deployment enforcement remains an integration requirement. |
