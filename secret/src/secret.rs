// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

use crate::{envelope::Envelope, vault::VaultSecret};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecretType {
    KMS(Envelope),
    Vault(VaultSecret),
}

#[derive(Serialize, Deserialize)]
pub struct Secret {
    version: String,

    #[serde(flatten)]
    r#type: SecretType,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_json_diff::assert_json_eq;
    use kms::{kms::KMSEnum, vault::VaultEnum};
    use serde_json::json;

    use crate::{
        envelope::{Envelope, WrapType},
        vault::VaultSecret,
    };

    use super::{Secret, SecretType};

    #[test]
    fn serialize_enveloped_secret() {
        let secret = Secret {
            version: "0.1.0".into(),
            r#type: SecretType::KMS(Envelope {
                provider: KMSEnum::Ali,
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
            r#type: SecretType::Vault(VaultSecret {
                provider: VaultEnum::Ali,
                annotations: HashMap::new(),
            }),
        };

        let expected = json!({
            "version": "0.1.0",
            "type": "Vault",
            "provider": "Ali",
            "annotations": {}
        });
        let serialized = serde_json::to_value(&secret).expect("serialize failed");
        assert_json_eq!(serialized, expected);
    }
}
