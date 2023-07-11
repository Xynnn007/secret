// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::*;
use base64::Engine;
use crypto::WrapType;
use kbs_client::Client as KbsClient;
use serde::{Deserialize, Serialize};

use resource_uri::ResourceUri;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// `AnnotationPacketV1` is what a encrypted image layer's
/// `org.opencontainers.image.enc.keys.provider.attestation-agent`
/// annotation should contain when it is encrypted by CoCo's
/// encryption modules. Please refer to issue
/// <https://github.com/confidential-containers/guest-components/issues/218>
///
/// This is an old version format of AnnotationPacket
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct AnnotationPacketV1 {
    /// Key ID to manage multiple keys
    pub kid: ResourceUri,

    /// Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,

    /// Initialisation vector (base64-encoded)
    pub iv: String,

    /// Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

impl AnnotationPacketV1 {
    pub async fn unwrap_key_with(self, kbs_client: Arc<Mutex<KbsClient>>) -> Result<Vec<u8>> {
        let key = {
            let mut client = kbs_client.lock().await;
            Zeroizing::new(client.get_resource(self.kid).await?)
        };

        let decoder = base64::engine::general_purpose::STANDARD;
        let iv = decoder.decode(&self.iv).context("decode iv")?;
        let wrap_type = WrapType::try_from(&self.wrap_type[..]).context("parse wrap type")?;
        let wrapped_data = decoder
            .decode(&self.wrapped_data)
            .context("decode wrapped data")?;

        crypto::decrypt(key, wrapped_data, iv, wrap_type)
    }
}
