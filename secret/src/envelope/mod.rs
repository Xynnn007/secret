// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use base64::Engine;
use crypto::WrapType as OutWrapType;
use kms::kms::KMSEnum;
use serde::{Deserialize, Serialize};
use strum::AsRefStr;
use zeroize::Zeroizing;

#[derive(AsRefStr, Serialize, Deserialize)]
pub enum WrapType {
    Aes256Gcm,
    Aes256Ctr,
}

impl From<WrapType> for OutWrapType {
    fn from(value: WrapType) -> Self {
        match value {
            WrapType::Aes256Gcm => OutWrapType::Aes256Gcm,
            WrapType::Aes256Ctr => OutWrapType::Aes256Ctr,
        }
    }
}

/// An Envelope is a secret encrypted by digital envelope mechanism.
/// It can be described as
///
/// {Enc(KMS, DEK), Enc(DEK, secret), paras...}
///
/// where Enc(A,B) means use key A to encrypt B
#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub provider: KMSEnum,

    /// key id to locate the key inside KMS
    pub key_id: String,

    /// Encrypted DEK by key inside KMS
    pub encrypted_key: String,

    /// Encrypted data (secret) by DEK
    pub encrypted_data: String,

    /// Encryption scheme of the Encrypted data by DEK
    pub wrap_type: WrapType,

    /// IV of encrypted_data, if used
    pub iv: String,

    /// KMS specific fields to locate the Key inside KMS
    pub annotations: HashMap<String, String>,
}

impl Envelope {
    pub async fn open(&self) -> Result<Vec<u8>> {
        let mut client = self.provider.to_client().await?;
        let base64_decoder = base64::engine::general_purpose::STANDARD;
        let enc_dek = base64_decoder.decode(&self.encrypted_key)?;
        let datakey = Zeroizing::new(
            client
                .decrypt(&enc_dek, &self.key_id, &self.annotations)
                .await?,
        );
        let iv = base64_decoder.decode(&self.iv)?;
        let ciphertext = base64_decoder.decode(&self.encrypted_data)?;
        crypto::decrypt(datakey, ciphertext, iv, self.wrap_type.as_ref())
    }
}
