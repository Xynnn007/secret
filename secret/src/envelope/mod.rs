// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod ali;

use std::collections::HashMap;

use anyhow::*;
use base64::Engine;
use crypto::WrapType as OutWrapType;
use kms::kms::KMSEnum;
use rand::Rng;
use serde::{Deserialize, Serialize};
use strum::AsRefStr;
use zeroize::{Zeroize, Zeroizing};

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

    pub async fn seal(provider: KMSEnum, keyid: String, data: Vec<u8>) -> Result<Self> {
        // Let's use a safer rand crate then
        let mut symmetric_key = [0u8; 32];
        rand::thread_rng().fill(&mut symmetric_key);
        let mut symmetric_iv = [0u8; 12];
        rand::thread_rng().fill(&mut symmetric_iv);

        let ciphertext = crypto::encrypt(
            Zeroizing::new(symmetric_key.to_vec()),
            data,
            symmetric_iv.to_vec(),
            "A256GCM",
        )?;

        let annotations = match provider {
            KMSEnum::Ali => ali::generate_annotation(),
        };

        let mut client = provider.to_client().await?;
        let encrypted_key = client.encrypt(&symmetric_key, &keyid, &annotations).await?;
        symmetric_key.zeroize();
        let base64_encoder = base64::engine::general_purpose::STANDARD;
        let envelope = Envelope {
            provider,
            key_id: keyid,
            encrypted_key: base64_encoder.encode(encrypted_key),
            encrypted_data: base64_encoder.encode(ciphertext),
            wrap_type: WrapType::Aes256Gcm,
            iv: base64_encoder.encode(symmetric_iv),
            annotations,
        };
        Ok(envelope)
    }
}
