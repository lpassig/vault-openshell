// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire identity shared with runtimes even when the authorization engine is absent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxIntent {
    pub gateway_id: String,
    pub sandbox_id: String,
    pub workspace: String,
    pub owner: String,
    pub policy_digest: String,
    pub driver: String,
    pub generation: String,
    pub auth_epoch: u64,
    pub expected_spiffe_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub decision_id: String,
    pub intent: SandboxIntent,
    pub device_id: String,
    pub device_revision: String,
    pub host_id: Option<String>,
    pub runtime_identity: Option<String>,
    pub proof_key_digest: Option<String>,
    pub selectors: BTreeSet<String>,
    pub challenge: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub scopes: BTreeSet<String>,
}
