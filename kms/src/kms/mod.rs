// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Drivers of KMS

pub mod ali;

use std::collections::HashMap;

use anyhow::{bail, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use strum::EnumString;

#[async_trait]
pub trait KMS: Send {
    /// Use the key of `keyid` to encrypt the `data` slice inside KMS, and then
    /// return the ciphertext of the `data`. The encryption operation should occur
    /// inside KMS. This function only works as a wrapper for different KMS APIs.
    ///
    /// Extra parameters can be included in `annotations`.
    async fn encrypt(
        &mut self,
        _data: &[u8],
        _keyid: &str,
        _annotations: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        bail!("Unimplemented!")
    }

    /// Use the key of `keyid` to decrypt the `ciphertext` slice inside KMS, and then
    /// return the plaintext of the `data`. The decryption operation should occur
    /// inside KMS. This function only works as a wrapper for different KMS APIs
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        keyid: &str,
        annotations: &HashMap<String, String>,
    ) -> Result<Vec<u8>>;
}

/// An Enum of all the supported KMS
#[derive(Clone, EnumString, Serialize, Deserialize)]
pub enum KMSEnum {
    Ali,
}

impl KMSEnum {
    pub async fn to_client(&self) -> Result<Box<dyn KMS>> {
        match self {
            KMSEnum::Ali => Ok(Box::new(ali::Client::from_env()?)),
        }
    }
}
