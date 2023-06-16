// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use tokio::process;

use super::KMS;

pub struct Client {
    kms_binary_path: String,
}

impl Client {
    pub fn from_env() -> Result<Self> {
        let kms_binary_path = std::env::var("KMS_BINARY_PATH")?;
        Ok(Self { kms_binary_path })
    }
}

#[async_trait]
impl KMS for Client {
    async fn encrypt(
        &mut self,
        data: &[u8],
        keyid: &str,
        annotations: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let plaintext = base64::engine::general_purpose::STANDARD.encode(data);
        let iv = annotations
            .get("iv")
            .ok_or_else(|| anyhow!("no iv provided"))?;
        let child = process::Command::new(&self.kms_binary_path)
            .arg("encrypt")
            .arg(plaintext)
            .arg(keyid)
            .arg(iv)
            .spawn()?;

        let res = child.wait_with_output().await?;
        let ciphertext = base64::engine::general_purpose::STANDARD.decode(res.stdout)?;
        Ok(ciphertext)
    }

    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        keyid: &str,
        annotations: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let cipher = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        let iv = annotations
            .get("iv")
            .ok_or_else(|| anyhow!("no iv provided"))?;
        let child = process::Command::new(&self.kms_binary_path)
            .arg("decrypt")
            .arg(cipher)
            .arg(keyid)
            .arg(iv)
            .spawn()?;

        let res = child.wait_with_output().await?;
        let plaintext = base64::engine::general_purpose::STANDARD.decode(res.stdout)?;
        Ok(plaintext)
    }
}
