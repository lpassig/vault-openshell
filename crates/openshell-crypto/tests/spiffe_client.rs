// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(feature = "aws-lc", feature = "openssl"))]

mod common;

use openshell_crypto::{pki, tls};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType};
use rustls::{
    RootCertStore,
    pki_types::{PrivatePkcs8KeyDer, UnixTime},
    server::WebPkiClientVerifier,
};
use std::{sync::Arc, time::Duration};

const SUPERVISOR: &str = "spiffe://example.org/openshell/sandbox/sandbox-a/generation/gen-a";
const OLD_SUPERVISOR: &str = "spiffe://example.org/openshell/sandbox/sandbox-a/generation/gen-old";
const OTHER_WORKLOAD: &str = "spiffe://example.org/openshell/sandbox/sandbox-b/generation/gen-a";

fn ca() -> pki::CertifiedKey {
    let key_pair = pki::generate_keypair().unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let cert = pki::self_signed(params, &key_pair).unwrap();
    pki::CertifiedKey { cert, key_pair }
}

fn client_certificate(issuer: &pki::CertifiedKey, uris: &[&str]) -> pki::CertifiedKey {
    let key_pair = pki::generate_keypair().unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = uris
        .iter()
        .map(|uri| SanType::URI((*uri).try_into().unwrap()))
        .collect();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = pki::signed_by(params, &key_pair, &issuer.cert, &issuer.key_pair).unwrap();
    pki::CertifiedKey { cert, key_pair }
}

#[test]
fn authenticated_tls_peer_still_needs_the_exact_current_spiffe_identity() {
    #[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
    common::init_openssl();

    let workload_ca = ca();
    let other_client_ca = ca();
    let mut workload_roots = RootCertStore::empty();
    workload_roots.add(workload_ca.cert.der().clone()).unwrap();
    let mut listener_roots = workload_roots.clone();
    listener_roots
        .add(other_client_ca.cert.der().clone())
        .unwrap();
    let verifier =
        tls::spiffe::SpiffeClientVerifier::new("example.org".into(), workload_roots).unwrap();

    let gateway = pki::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut gateway_roots = RootCertStore::empty();
    gateway_roots.add(gateway.cert.der().clone()).unwrap();
    let listener = tls::try_server_builder()
        .unwrap()
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(
                Arc::new(listener_roots),
                tls::configuration_provider(),
            )
            .allow_unauthenticated()
            .build()
            .unwrap(),
        )
        .with_single_cert(
            vec![gateway.cert.der().clone()],
            PrivatePkcs8KeyDer::from(gateway.key_pair.serialize_der().unwrap()).into(),
        )
        .unwrap();
    let connect = |credential: Option<&pki::CertifiedKey>| {
        let builder = tls::try_client_builder()
            .unwrap()
            .with_root_certificates(gateway_roots.clone());
        let client = match credential {
            Some(credential) => builder
                .with_client_auth_cert(
                    vec![credential.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(credential.key_pair.serialize_der().unwrap()).into(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        common::handshake(client, listener.clone(), "localhost")
            .unwrap()
            .1
    };

    let now = UnixTime::now();
    let peer = connect(Some(&client_certificate(&workload_ca, &[SUPERVISOR])));
    let identity = verifier.verify_peer(&peer, now).unwrap();
    let expiry = identity.authorize(SUPERVISOR, now).unwrap();
    let at_expiry = UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(expiry).unwrap()));
    assert!(identity.authorize(SUPERVISOR, at_expiry).is_err());
    assert!(verifier.verify_peer(&connect(None), now).is_err());

    for uri in [OTHER_WORKLOAD, OLD_SUPERVISOR] {
        let peer = connect(Some(&client_certificate(&workload_ca, &[uri])));
        let other = verifier.verify_peer(&peer, now).unwrap();
        assert!(other.authorize(SUPERVISOR, now).is_err());
    }
    for (issuer, uris) in [
        (&other_client_ca, &[SUPERVISOR][..]),
        (&workload_ca, &[SUPERVISOR, OTHER_WORKLOAD][..]),
        (&workload_ca, &[][..]),
        (
            &workload_ca,
            &["spiffe://other.example/openshell/sandbox/sandbox-a/generation/gen-a"][..],
        ),
    ] {
        let peer = connect(Some(&client_certificate(issuer, uris)));
        assert!(verifier.verify_peer(&peer, now).is_err());
    }
}
