// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use crypto::WrapType as OutWrapType;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub enum KMSProvider {
    Ali,
}

/// An Envelope is a secret encrypted by digital envelope mechanism.
/// It can be described as
///
/// {Enc(KMS, DEK), Enc(DEK, secret), paras...}
///
/// where Enc(A,B) means use key A to encrypt B
#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub provider: KMSProvider,

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
