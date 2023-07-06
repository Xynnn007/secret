// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod layout;

use serde::{Deserialize, Serialize};
use strum::EnumString;

use self::layout::{envelope::Envelope, vault::VaultSecret};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecretContent {
    Envelope(Envelope),
    Vault(VaultSecret),
}

#[derive(Serialize, Deserialize)]
pub struct Secret {
    pub version: String,

    /// decryptor driver of the secret
    pub provider: String,

    #[serde(flatten)]
    pub r#type: SecretContent,
}

#[derive(EnumString)]
pub enum SealType {
    Envelope,
    Vault,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_json_diff::assert_json_eq;
    use crypto::WrapType;
    use serde_json::json;

    use crate::secret::layout::{envelope::Envelope, vault::VaultSecret};

    use super::{Secret, SecretContent};

    #[test]
    fn serialize_enveloped_secret() {
        let secret = Secret {
            version: "0.1.0".into(),
            provider: "ali".into(),
            r#type: SecretContent::Envelope(Envelope {
                key_id: "xxx".into(),
                encrypted_key: "yyy".into(),
                encrypted_data: "zzz".into(),
                wrap_type: WrapType::Aes256Gcm,
                iv: "www".into(),
                annotations: HashMap::new(),
            }),
        };

        let expected = json!({
            "version": "0.1.0",
            "type": "KMS",
            "provider": "Ali",
            "key_id": "xxx",
            "encrypted_key": "yyy",
            "encrypted_data": "zzz",
            "wrap_type": "Aes256Gcm",
            "iv": "www",
            "annotations": {}
        });
        let serialized = serde_json::to_value(&secret).expect("serialize failed");
        assert_json_eq!(serialized, expected);
    }

    #[test]
    fn serialize_vault_secret() {
        let secret = Secret {
            version: "0.1.0".into(),
            provider: "ali".into(),
            r#type: SecretContent::Vault(VaultSecret {
                annotations: HashMap::new(),
                name: "xxx".into(),
            }),
        };

        let expected = json!({
            "version": "0.1.0",
            "type": "Vault",
            "provider": "Ali",
            "name": "xxx",
            "annotations": {}
        });
        let serialized = serde_json::to_value(&secret).expect("serialize failed");
        assert_json_eq!(serialized, expected);
    }
}
