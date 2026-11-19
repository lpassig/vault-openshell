# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

package openshell.bootstrap

import rego.v1

default decision := {"allow": false, "reason": "policy_denied", "ttl_secs": 0, "scopes": []}

# All attributes are supplied by gateway verification, never request labels.
decision := {"allow": true, "reason": "bootstrap_admitted", "ttl_secs": 60, "scopes": ["bootstrap"]} if {
    input.stage == "bootstrap"
    input.intent.owner != ""
    input.intent.workspace != ""
    input.intent.policy_digest != ""
    input.intent.driver != ""
    input.device_id != ""
    input.device_revision != ""
    input.expires_at > input.now
}

decision := {"allow": true, "reason": "provider_admitted", "ttl_secs": 30, "scopes": ["provider_access"]} if {
    input.stage == "provider"
    input.parent_decision_id != ""
    input.proof_verified
    count(input.selectors) > 0
    input.host_id != ""
    input.host_id != null
    input.runtime_identity != ""
    input.spiffe_id == input.intent.expected_spiffe_id
    input.expires_at > input.now
}

decision := {"allow": true, "reason": "configuration_admitted", "ttl_secs": 30, "scopes": ["configuration_activation"]} if {
    input.stage == "activation"
    input.intent.driver == "docker"
    input.parent_decision_id != ""
    input.proof_verified
    count(input.selectors) > 0
    input.host_id != null
    input.runtime_identity != ""
    input.spiffe_id != null
    input.resource != ""
    input.expires_at > input.now
}

decision := {"allow": true, "reason": "renewal_admitted", "ttl_secs": 30, "scopes": ["bootstrap"]} if {
    input.stage == "renewal"
    input.intent.driver == "kubernetes"
    input.parent_decision_id != ""
    input.proof_verified
    count(input.selectors) > 0
    input.host_id != ""
    input.host_id != null
    input.runtime_identity != ""
    input.spiffe_id == input.intent.expected_spiffe_id
    input.resource == "/openshell.v1.OpenShell/RefreshSandboxToken"
    input.expires_at > input.now
}
