// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VaultSecret {
    /// The id of this secret
    pub name: String,

    /// decryptor driver of the secret
    pub provider: String,

    /// Other fields used to fetch the secret
    pub annotations: HashMap<String, String>,
}

impl VaultSecret {
    /// Retrieve this secret. If this secret is a KBS-version vault
    /// secret, the field `name` is the KBS Resource ID of the secret
    /// from the kbs.
    pub(crate) async fn unseal(&self) -> Result<Vec<u8>> {
        match &self.provider[..] {
            "kbs" => {
                let client = new_kbs_client();
                let secret_url = ResourceUri::try_from(&self.name[..])
                    .map_err(|e| anyhow!("parse `name` as resource uri failed: {e}"))?;
                client.get_resource(secret_url).await
            }
            other => {
                let mut client = kms::newer::Kms::new_decryptor(other, self.annotations).await?;
                client.get_secret(&self.name, &self.annotations).await
            }
        }
    }
}

//     /// Create a vault secret of the data with the given KbsClient. The
//     /// data will be stored inside the vault with name `name`.
//     pub async fn seal_with_kbs(
//         _name: String,
//         _data: Vec<u8>,
//         _sealer: Arc<Mutex<KbsClient>>,
//     ) -> Result<Self> {
//         todo!()
//     }

//     /// Create a vault secret of the data with the given KbsClient. The
//     /// data will be stored inside the vault with name `name`.
//     pub async fn seal_with_kms(
//         name: String,
//         data: Vec<u8>,
//         sealer: Arc<Mutex<dyn KMS>>,
//     ) -> Result<Self> {
//         let annotations = {
//             let mut client = sealer.lock().await;
//             client.set_secret(data, name.clone()).await?
//         };

//         Ok(Self { name, annotations })
//     }
// }
