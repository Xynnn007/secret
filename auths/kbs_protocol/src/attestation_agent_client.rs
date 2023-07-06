// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Client to connect to the attestation-agent. This module should be
//! replaced with a client lib inside attestation-agent.

use anyhow::*;
use kbs_types::Tee;
use tonic::transport::Channel;

use self::attestation_agent::{
    attestation_agent_service_client::AttestationAgentServiceClient, GetAttesterTypeRequest,
    GetEvidenceRequest,
};

mod attestation_agent {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::redundant_async_block)]
    tonic::include_proto!("attestation_agent");
}

const AA_POD_DOMAIN: &str = "http://attestation-agent";

pub struct Client {
    inner: AttestationAgentServiceClient<Channel>,
}

impl Client {
    pub async fn new() -> Result<Self> {
        let inner = AttestationAgentServiceClient::connect(AA_POD_DOMAIN).await?;
        Ok(Self { inner })
    }

    pub async fn detect_tee_type(&mut self) -> Result<Tee> {
        let req = tonic::Request::new(GetAttesterTypeRequest {});
        let res = self
            .inner
            .get_attester_type(req)
            .await
            .context("call GetAttesterType API failed")?
            .into_inner();
        let typ: Tee = serde_json::from_str(&res.r#type)
            .context(format!("Unknown Tee Type {}", res.r#type))?;
        Ok(typ)
    }

    pub async fn get_evidence(&mut self, challenge: String) -> Result<Vec<u8>> {
        let req = tonic::Request::new(GetEvidenceRequest { challenge });
        let res = self
            .inner
            .get_evidence(req)
            .await
            .context("call GetAttesterType API failed")?
            .into_inner();
        Ok(res.evidence)
    }
}

#[cfg(test)]
mod tests {
    use kbs_types::Tee;
    use rstest::rstest;

    #[rstest]
    #[case("\"sgx\"", Tee::Sgx)]
    #[case("\"sev\"", Tee::Sev)]
    #[case("\"tdx\"", Tee::Tdx)]
    #[case("\"azsnpvtpm\"", Tee::AzSnpVtpm)]
    #[case("\"snp\"", Tee::Snp)]
    #[case("\"cca\"", Tee::Cca)]
    #[case("\"sample\"", Tee::Sample)]
    fn parse_tee_type(#[case] name: &str, #[case] expected_tee: Tee) {
        let typ: Tee = serde_json::from_str(name).expect("parse tee failed");
        assert_eq!(typ, expected_tee);
    }
}
