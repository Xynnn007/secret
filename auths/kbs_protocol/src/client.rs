// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

use anyhow::*;
use async_recursion::async_recursion;
use base64::Engine;
use crypto::{rust::rsa::PaddingMode, WrapType};
use kbs_types::{Attestation, Challenge, ErrorInformation, Request, Response, Tee};
use log::info;
use resource_uri::ResourceUri;
use serde::Deserialize;
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

use crate::{attestation_agent_client, tee_pubkey::TeeKeyPair, KBS_PROTOCOL_VERSION};

const KBS_REQ_TIMEOUT_SEC: u64 = 60;

pub const KBS_URL_PREFIX: &str = "kbs/v0";

/// This Handshaker is used to connect to the remote KBS. Also, it will call
/// the local attestation-agent to gather enough evidence for handshake.
pub struct Handshaker {
    /// TEE Type
    tee: Tee,

    /// The asymmetric key pair inside the TEE
    pub tee_key: Option<TeeKeyPair>,

    /// Used to connect to the local attestation-agent to get the evidence
    aa_client: attestation_agent_client::Client,

    /// Http client
    http_client: reqwest::Client,

    /// KBS Host URL
    kbs_host_url: Option<String>,
}

impl Handshaker {
    pub async fn new() -> Result<Handshaker> {
        // Create a connection to the attestation-agent
        let mut aa_client = attestation_agent_client::Client::new().await?;

        // Detect TEE type of the current platform.
        let tee = aa_client.detect_tee_type().await?;

        let http_client = reqwest::Client::builder()
            .cookie_store(true)
            .user_agent(format!(
                "attestation-agent-kbs-client/{}",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(Duration::from_secs(KBS_REQ_TIMEOUT_SEC))
            .build()
            .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))?;

        Ok(Handshaker {
            tee,
            tee_key: None,
            aa_client,
            http_client,
            kbs_host_url: None,
        })
    }

    async fn generate_evidence(&mut self, nonce: String, tee_key: Vec<&[u8]>) -> Result<String> {
        let mut hasher = Sha384::new();
        let engine = base64::engine::general_purpose::STANDARD;
        hasher.update(nonce.as_bytes());
        tee_key
            .iter()
            .for_each(|key_material| hasher.update(key_material));
        let ehd = engine.encode(hasher.finalize());

        let tee_evidence = self
            .aa_client
            .get_evidence(ehd)
            .await
            .map_err(|e| anyhow!("Get TEE evidence failed: {:?}", e))
            .and_then(|c| Ok(base64::engine::general_purpose::STANDARD.encode(c)))?;

        Ok(tee_evidence)
    }

    pub async fn handshake(&mut self, kbs_host_url: String) -> Result<String> {
        let request = Request {
            version: KBS_PROTOCOL_VERSION.into(),
            tee: self.tee.clone(),
            extra_params: String::new(),
        };

        let challenge = self
            .http_client
            .post(format!("{kbs_host_url}/{KBS_URL_PREFIX}/auth"))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?
            .json::<Challenge>()
            .await?;

        let tee_keypair = TeeKeyPair::new()?;
        let tee_pubkey = tee_keypair.export_pubkey()?;
        let materials = vec![tee_pubkey.k_mod.as_bytes(), tee_pubkey.k_exp.as_bytes()];

        let tee_evidence = self.generate_evidence(challenge.nonce, materials).await?;
        let attestation = Attestation {
            tee_pubkey,
            tee_evidence,
        };
        let attest_response = self
            .http_client
            .post(format!("{kbs_host_url}/{KBS_URL_PREFIX}/attest"))
            .header("Content-Type", "application/json")
            .json(&attestation)
            .send()
            .await?;

        match attest_response.status() {
            reqwest::StatusCode::OK => {
                self.tee_key = Some(tee_keypair);
                self.kbs_host_url = Some(kbs_host_url);
                let token = attest_response.json::<serde_json::Value>().await?["token"].to_string();
                Ok(token)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                let error_info = attest_response.json::<ErrorInformation>().await?;
                bail!("KBS attest unauthorized, Error Info: {:?}", error_info)
            }
            _ => {
                bail!(
                    "KBS Server Internal Failed, Response: {:?}",
                    attest_response.text().await?
                )
            }
        }
    }

    fn decrypt_response(&self, response: Response) -> Result<Vec<u8>> {
        // deserialize the jose header and check that the key type matches
        let protected: ProtectedHeader = serde_json::from_str(&response.protected)?;
        if protected.alg != PaddingMode::PKCS1v15.as_ref() {
            bail!("Algorithm mismatch for wrapped key.");
        }

        let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        // unwrap the wrapped key
        let wrapped_symkey: Vec<u8> = decoder.decode(response.encrypted_key)?;
        let symkey: Vec<u8> = self
            .tee_key
            .as_ref()
            .ok_or_else(|| anyhow!("Handshake not called before!"))?
            .decrypt(PaddingMode::PKCS1v15, wrapped_symkey)?;

        let iv = decoder.decode(response.iv)?;
        let ciphertext = decoder.decode(response.ciphertext)?;

        let plaintext = crypto::decrypt(Zeroizing::new(symkey), ciphertext, iv, protected.enc)?;

        Ok(plaintext)
    }

    #[async_recursion]
    pub async fn get(&mut self, resource_url: ResourceUri, retry: bool) -> Result<Vec<u8>> {
        let kbs_host_url = self
            .kbs_host_url
            .as_ref()
            .ok_or_else(|| anyhow!("Handshake not called before!"))?;
        let url = format!(
            "{kbs_host_url}/{KBS_URL_PREFIX}/{}",
            resource_url.resource_path()
        );

        let res = self.http_client.get(url).send().await?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let response = res.json::<Response>().await?;
                let payload_data = self.decrypt_response(response)?;
                Ok(payload_data)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                if !retry {
                    bail!("Unauthorized request.");
                }
                info!("retry to auth again.");
                self.handshake(kbs_host_url.clone()).await?;
                self.get(resource_url, false).await
            }
            reqwest::StatusCode::NOT_FOUND => {
                bail!("KBS resource Not Found (Error 404)")
            }
            _ => {
                bail!(
                    "KBS Server Internal Failed, Response: {:?}",
                    res.text().await?
                )
            }
        }
    }
}

#[derive(Deserialize)]
struct ProtectedHeader {
    // enryption algorithm for encrypted key
    alg: String,
    // encryption algorithm for payload
    enc: WrapType,
}
