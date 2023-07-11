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
use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// New version format of AnnotationPacket
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct AnnotationPacketV2 {
    /// Version of the AnnotationPacket
    pub version: String,

    /// Key ID to manage multiple keys. If provider is `kbs`, this field
    /// should be a [`ResourceUri`]
    pub kid: String,

    /// Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,

    /// The way to decrypt this LEK, s.t. provider of the KEK.
    pub provider: String,

    /// Initialisation vector (base64-encoded). Only used when
    /// provider is `"kbs"`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,

    /// Wrap type to specify encryption algorithm and mode. Only used when
    /// provider is `"kbs"`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_type: Option<String>,

    /// more information to get the KEK
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

pub enum Unwrapper {
    Kms(Arc<Mutex<dyn KMS>>),
    Kbs(Arc<Mutex<KbsClient>>),
}

impl AnnotationPacketV2 {
    pub async fn unwrap_key_with(self, unwrapper: Unwrapper) -> Result<Vec<u8>> {
        match unwrapper {
            Unwrapper::Kbs(kbs_client) => {
                if self.provider != "kbs" {
                    bail!(
                        "The given provider is `kbs`, but the one of the KEK is {}",
                        self.provider
                    );
                }

                let wrap_type = self.wrap_type.clone().ok_or_else(|| anyhow!("The KEK is provided by `kbs` but no `WrapType` is defined inside the AnnotationPacket"))?;
                let iv = self.iv.clone().ok_or_else(|| anyhow!("The KEK is provided by `kbs` but no `iv` is defined inside the AnnotationPacket"))?;

                let resource_uri = ResourceUri::try_from(&self.kid[..])
                    .map_err(|e| anyhow!("cannot parse the kid into a KBS Resource URI: {e}"))?;
                let key = {
                    let mut client = kbs_client.lock().await;
                    Zeroizing::new(client.get_resource(resource_uri).await?)
                };
                let decoder = base64::engine::general_purpose::STANDARD;
                let iv = decoder.decode(&iv).context("decode iv")?;
                let wrap_type = WrapType::try_from(&wrap_type[..]).context("parse wrap type")?;
                let wrapped_data = decoder
                    .decode(&self.wrapped_data)
                    .context("decode wrapped data")?;

                crypto::decrypt(key, wrapped_data, iv, wrap_type)
            }
            Unwrapper::Kms(kms_client) => {
                let decoder = base64::engine::general_purpose::STANDARD;
                let wrapped_data = decoder
                    .decode(&self.wrapped_data)
                    .context("decode wrapped data")?;

                let mut client = kms_client.lock().await;
                let driver_name = client.name();
                if driver_name != self.provider {
                    bail!("cannot decrypt the LEK, because given KEK provider is {driver_name}, but {} expected", self.provider);
                }

                client
                    .decrypt(&wrapped_data, &self.kid, &self.annotations)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    use serde_json::{json, Value};

    use super::AnnotationPacketV2;

    #[rstest]
    #[case(json!({
        "version": "0.1.0",
        "kid": "kbs:///default/key/1",
        "wrapped_data": "xxx",
        "provider": "kbs",
        "iv": "yyy",
        "wrap_type": "A256GCM",
    }), AnnotationPacketV2 {
        version: "0.1.0".into(),
        kid: "kbs:///default/key/1".into(),
        wrapped_data: "xxx".into(),
        provider: "kbs".into(),
        iv: Some("yyy".into()),
        wrap_type: Some("A256GCM".into()),
        annotations: HashMap::new(),
    })]
    #[case(json!({
        "version": "0.1.0",
        "kid": "uuid00111",
        "wrapped_data": "xxx",
        "provider": "ali",
        "annotations": {
            "region": "cn-hangzhou",
            "instanceid": "xxx",
        }
    }), AnnotationPacketV2 {
        version: "0.1.0".into(),
        kid: "uuid00111".into(),
        wrapped_data: "xxx".into(),
        provider: "ali".into(),
        iv: None,
        wrap_type: None,
        annotations: [("region".into(), "cn-hangzhou".into()), ("instanceid".into(), "xxx".into())].into_iter().collect()
    })]
    fn serialize_v2_packet(#[case] expected: Value, #[case] given: AnnotationPacketV2) {
        let serialized = serde_json::to_value(given).expect("serialized failed");
        assert_json_eq!(serialized, expected);
    }

    #[rstest]
    #[case(r#"{
        "version": "0.1.0",
        "kid": "kbs:///default/key/1",
        "wrapped_data": "xxx",
        "provider": "kbs",
        "iv": "yyy",
        "wrap_type": "A256GCM",
        "annotations": {}
    }"#, AnnotationPacketV2 {
        version: "0.1.0".into(),
        kid: "kbs:///default/key/1".into(),
        wrapped_data: "xxx".into(),
        provider: "kbs".into(),
        iv: Some("yyy".into()),
        wrap_type: Some("A256GCM".into()),
        annotations: HashMap::new(),
    })]
    #[case(r#"{
        "version": "0.1.0",
        "kid": "uuid00111",
        "wrapped_data": "xxx",
        "provider": "ali",
        "annotations": {
            "region": "cn-hangzhou",
            "instanceid": "xxx"
        }
    }"#, AnnotationPacketV2 {
        version: "0.1.0".into(),
        kid: "uuid00111".into(),
        wrapped_data: "xxx".into(),
        provider: "ali".into(),
        iv: None,
        wrap_type: None,
        annotations: [("region".into(), "cn-hangzhou".into()), ("instanceid".into(), "xxx".into())].into_iter().collect()
    })]
    fn deserialize_v2_packet(#[case] given: &str, #[case] expected: AnnotationPacketV2) {
        let deserialized: AnnotationPacketV2 =
            serde_json::from_str(given).expect("serialized failed");
        assert_json_eq!(deserialized, expected);
    }
}
