// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, sync::Arc};

use anyhow::*;
use base64::Engine;
use crypto::WrapType;
use kbs_client::Client as KbsClient;
use kms::KMS;
use rand::Rng;
use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

/// An Envelope is a secret encrypted by digital envelope mechanism.
/// It can be described as
///
/// {Enc(KMS, DEK), Enc(DEK, secret), paras...}
///
/// where Enc(A,B) means use key A to encrypt B
///
/// The fields inside this Struct will be flattened in a Secret wrapper.
#[derive(Serialize, Deserialize)]
pub struct Envelope {
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
    /// Unseal this envelope with the given kbs client, which means this envelope
    /// must be sealed by kbs.
    pub(crate) async fn unseal_with_kbs(&self, unsealer: Arc<Mutex<KbsClient>>) -> Result<Vec<u8>> {
        let base64_decoder = base64::engine::general_purpose::STANDARD;
        let enc_dek = base64_decoder.decode(&self.encrypted_key)?;
        let datakey = {
            let key = {
                let mut client = unsealer.lock().await;
                let key_url = ResourceUri::try_from(&self.key_id[..])
                    .map_err(|e| anyhow!("parse key id as resource uri failed: {e}"))?;
                Zeroizing::new(client.get_resource(key_url).await?)
            };

            // If KBS is used as envelope secret, a IV field must be inside the annotations.
            // The format will be:
            //
            // Dek_enc = Enc(Key_{kbs}, Dek, A256GCM)
            // Data_enc = Enc(Dek, Data, WrapType)
            let iv = self
                .annotations
                .get("iv")
                .ok_or_else(|| anyhow!("No `iv` field given in a KBS-sealed envelope secret"))
                .and_then(|c| base64_decoder.decode(c).map_err(anyhow::Error::from))?;
            Zeroizing::new(crypto::decrypt(key, enc_dek, iv, WrapType::Aes256Gcm)?)
        };
        let iv = base64_decoder.decode(&self.iv)?;
        let ciphertext = base64_decoder.decode(&self.encrypted_data)?;
        crypto::decrypt(datakey, ciphertext, iv, self.wrap_type)
    }

    /// Unseal this envelope with the given kms client, which means this envelope
    /// must be sealed by kms.
    pub(crate) async fn unseal_with_kms(&self, unsealer: Arc<Mutex<dyn KMS>>) -> Result<Vec<u8>> {
        let base64_decoder = base64::engine::general_purpose::STANDARD;
        let enc_dek = base64_decoder.decode(&self.encrypted_key)?;
        let datakey = {
            let mut client = unsealer.lock().await;

            Zeroizing::new(
                client
                    .decrypt(&enc_dek, &self.key_id, &self.annotations)
                    .await?,
            )
        };
        let iv = base64_decoder.decode(&self.iv)?;
        let ciphertext = base64_decoder.decode(&self.encrypted_data)?;
        crypto::decrypt(datakey, ciphertext, iv, self.wrap_type)
    }

    /// Seal the given data with the given kbs client. The keyid is used
    /// by the kbs client and must be a resource URI.
    pub async fn seal_with_kbs(
        keyid: String,
        data: Vec<u8>,
        sealer: Arc<Mutex<KbsClient>>,
    ) -> Result<Self> {
        // Let's use a safer rand crate then
        let mut symmetric_key = [0u8; 32];
        rand::thread_rng().fill(&mut symmetric_key);
        let mut symmetric_iv = [0u8; 12];
        rand::thread_rng().fill(&mut symmetric_iv);

        let ciphertext = crypto::encrypt(
            Zeroizing::new(symmetric_key.to_vec()),
            data,
            symmetric_iv.to_vec(),
            WrapType::Aes256Gcm,
        )?;

        let (encrypted_key, annotations) = {
            let key = {
                let mut client = sealer.lock().await;
                let key_url = ResourceUri::try_from(&keyid[..])
                    .map_err(|e| anyhow!("parse key id as resource uri failed: {e}"))?;
                Zeroizing::new(client.get_resource(key_url).await?)
            };
            let mut sealed_iv = [0u8; 12];
            rand::thread_rng().fill(&mut sealed_iv);
            let engine = base64::engine::general_purpose::STANDARD;
            let sealed_iv_base64 = engine.encode(sealed_iv);

            let encrypted_key = crypto::encrypt(
                key,
                symmetric_key.to_vec(),
                sealed_iv.to_vec(),
                WrapType::Aes256Gcm,
            )?;
            let annotations = [("iv".into(), sealed_iv_base64)].into_iter().collect();
            (encrypted_key, annotations)
        };

        symmetric_key.zeroize();
        let base64_encoder = base64::engine::general_purpose::STANDARD;
        let envelope = Envelope {
            key_id: keyid,
            encrypted_key: base64_encoder.encode(encrypted_key),
            encrypted_data: base64_encoder.encode(ciphertext),
            wrap_type: WrapType::Aes256Gcm,
            iv: base64_encoder.encode(symmetric_iv),
            annotations,
        };
        Ok(envelope)
    }

    /// Seal the given data with the given KMS driver. The keyid is used
    /// by the KMS driver.
    pub async fn seal_with_kms(
        keyid: String,
        data: Vec<u8>,
        sealer: Arc<Mutex<dyn KMS>>,
    ) -> Result<Self> {
        // Let's use a safer rand crate then
        let mut symmetric_key = [0u8; 32];
        rand::thread_rng().fill(&mut symmetric_key);
        let mut symmetric_iv = [0u8; 12];
        rand::thread_rng().fill(&mut symmetric_iv);

        let ciphertext = crypto::encrypt(
            Zeroizing::new(symmetric_key.to_vec()),
            data,
            symmetric_iv.to_vec(),
            WrapType::Aes256Gcm,
        )?;

        let (encrypted_key, annotations) = {
            let mut client = sealer.lock().await;
            client.encrypt(&symmetric_key, &keyid).await?
        };

        symmetric_key.zeroize();
        let base64_encoder = base64::engine::general_purpose::STANDARD;
        let envelope = Envelope {
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
