// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor proof of possession for an independently enrolled assignment key.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use miette::{Result, miette};
use serde::Deserialize;

use crate::bootstrap_identity::{
    ProofClaims, RENEWAL_RESOURCE, RENEWAL_SVID_AUDIENCE, WORKLOAD_PROOF_ISSUER,
    WORKLOAD_PROOF_TTL_SECS, WORKLOAD_PROOF_TYPE,
};
use crate::jwt::{
    CredentialEpoch, JwtClock, SecretPrivateKeyPem, SessionJwtVerifier, SessionTokenProfile,
    SessionVerificationKey, SupervisorAuthBundle, SystemJwtClock,
};
use crate::sandbox_generation::SandboxGenerationId;

/// Operator-provisioned material on the trusted supervisor. The posture
/// authority independently enrolls the matching public key for the assignment.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrolledWorkloadKey {
    gateway_id: String,
    runtime_identity: String,
    verification_keys: Vec<SessionVerificationKey>,
    private_key_pem: SecretPrivateKeyPem,
}

#[derive(Clone)]
pub struct BootstrapProofSigner {
    directory: PathBuf,
    key_file: String,
    sandbox_id: String,
    generation: SandboxGenerationId,
    auth_epoch: CredentialEpoch,
}

impl BootstrapProofSigner {
    pub fn new(
        directory: PathBuf,
        sandbox_id: &str,
        bundle: &SupervisorAuthBundle,
    ) -> Result<Self> {
        if !directory.is_absolute() || SandboxGenerationId::parse(sandbox_id).is_err() {
            return Err(miette!(
                "invalid workload key directory or sandbox identity"
            ));
        }
        let generation = SandboxGenerationId::parse(bundle.runtime_generation.as_str())
            .map_err(|_| miette!("invalid workload key generation"))?;
        let auth_epoch = CredentialEpoch::new(bundle.auth_epoch.get())
            .map_err(|_| miette!("invalid workload key epoch"))?;
        Ok(Self {
            directory,
            key_file: format!("{sandbox_id}.{generation}.{}.json", auth_epoch.get()),
            sandbox_id: sandbox_id.into(),
            generation,
            auth_epoch,
        })
    }

    pub fn sign(&self, bearer: &str, resource: &str, svid_audience: &str) -> Result<String> {
        if resource.is_empty() || svid_audience.is_empty() {
            return Err(miette!(
                "workload proof does not match the current assignment"
            ));
        }
        // Enrollment may be established after the assignment is dispatched.
        // Read current material at use and deny if absent, moved or invalid.
        let enrolled = read_enrollment(&self.directory, &self.key_file)?;
        let verifier = SessionJwtVerifier::new(
            &enrolled.gateway_id,
            SessionTokenProfile::Gateway,
            enrolled.verification_keys,
            Arc::new(SystemJwtClock),
        )
        .map_err(|_| miette!("invalid gateway verification keys for workload proof"))?;
        let session = verifier
            .verify(bearer)
            .map_err(|_| miette!("invalid gateway session token for workload proof"))?;
        let grant = session
            .bootstrap
            .as_ref()
            .ok_or_else(|| miette!("workload proof requires a bootstrap launch token"))?;
        if session.sandbox_id.as_str() != self.sandbox_id
            || session.runtime_generation != self.generation
            || session.auth_epoch != self.auth_epoch
            || grant.intent.gateway_id != enrolled.gateway_id
            || grant.intent.driver != "kubernetes"
            || !enrolled.runtime_identity.starts_with("kubernetes://")
        {
            return Err(miette!(
                "workload key does not match the sandbox assignment"
            ));
        }
        let signing_key =
            EncodingKey::from_ed_pem(enrolled.private_key_pem.expose_secret().as_bytes())
                .map_err(|_| miette!("invalid Ed25519 workload key"))?;
        let now = SystemJwtClock.now_unix_seconds();
        let current_expiration = session.expires_at.min(grant.expires_at);
        if current_expiration <= now {
            return Err(miette!("bootstrap grant expired"));
        }
        let proof_expiration = now.saturating_add(WORKLOAD_PROOF_TTL_SECS);
        // The gateway checks that the old bearer is still live at renewal.
        // Its expiry caps use of this proof, while the new decision gets a
        // fresh deadline bounded by the proof and renewed evidence.
        let exp = if resource == RENEWAL_RESOURCE && svid_audience == RENEWAL_SVID_AUDIENCE {
            proof_expiration
        } else {
            proof_expiration.min(current_expiration)
        };
        let nonce = openshell_crypto::random_bytes::<16>()
            .map_err(|_| miette!("cannot generate a workload proof nonce"))?;
        let claims = ProofClaims {
            iss: WORKLOAD_PROOF_ISSUER.into(),
            sub: grant.intent.expected_spiffe_id.clone(),
            aud: grant.intent.gateway_id.clone(),
            iat: now,
            exp,
            jti: uuid::Uuid::from_bytes(nonce).to_string(),
            decision_id: grant.decision_id.clone(),
            challenge: grant.challenge.clone(),
            sandbox_id: session.sandbox_id.to_string(),
            generation: session.runtime_generation.to_string(),
            auth_epoch: session.auth_epoch.get(),
            gateway_token_id: session.token_id.to_string(),
            device_id: grant.device_id.clone(),
            runtime_identity: enrolled.runtime_identity,
            resource: resource.into(),
            svid_audience: svid_audience.into(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(WORKLOAD_PROOF_TYPE.into());
        openshell_crypto::jwt::encode(&header, &claims, &signing_key)
            .map_err(|_| miette!("cannot sign workload proof"))
    }
}

#[cfg(unix)]
fn read_enrollment(directory: &Path, name: &str) -> Result<EnrolledWorkloadKey> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt;

    const MAX_ENROLLMENT: u64 = 65_536;
    let unavailable = |_| miette!("cannot read the enrolled workload key");
    let directory = open(
        directory,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(unavailable)?;
    let file = openat(
        &directory,
        name,
        OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(unavailable)?;
    let file = std::fs::File::from(file);
    let metadata = file
        .metadata()
        .map_err(|_| miette!("cannot stat the enrolled workload key"))?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_ENROLLMENT
    {
        return Err(miette!(
            "enrolled workload key must be a private regular file"
        ));
    }
    let mut data = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_ENROLLMENT + 1)
        .read_to_end(&mut data)
        .map_err(|_| miette!("cannot read the enrolled workload key"))?;
    if data.len() as u64 > MAX_ENROLLMENT {
        return Err(miette!("enrolled workload key exceeds the size limit"));
    }
    serde_json::from_slice(&data).map_err(|_| miette!("invalid enrolled workload key"))
}

#[cfg(not(unix))]
fn read_enrollment(_: &Path, _: &str) -> Result<EnrolledWorkloadKey> {
    Err(miette!("workload key files require a Unix supervisor"))
}
