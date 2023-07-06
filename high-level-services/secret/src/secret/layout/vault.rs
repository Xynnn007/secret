// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, sync::Arc};

use anyhow::*;
use kbs_client::Client as KbsClient;
use kms::KMS;
use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize)]
pub struct VaultSecret {
    /// The id of this secret
    pub name: String,

    /// Other fields used to fetch the secret
    pub annotations: HashMap<String, String>,
}

impl VaultSecret {
    /// Retrieve this secret. If this secret is a KBS-version vault
    /// secret, the field `name` is the KBS Resource ID of the secret
    /// from the kbs.
    pub(crate) async fn unseal_with_kbs(&self, unsealer: Arc<Mutex<KbsClient>>) -> Result<Vec<u8>> {
        let secret_url = ResourceUri::try_from(&self.name[..])
            .map_err(|e| anyhow!("parse `name` as resource uri failed: {e}"))?;
        let secret = {
            let client = unsealer.lock().await;
            client.get_resource(&secret_url).await?
        };

        Ok(secret)
    }

    /// Retrieve this secret from a given KMS client driver
    pub(crate) async fn unseal_with_kms(&self, unsealer: Arc<Mutex<dyn KMS>>) -> Result<Vec<u8>> {
        let secret = {
            let mut client = unsealer.lock().await;

            client.get_secret(&self.name, &self.annotations).await?
        };

        Ok(secret)
    }

    /// Create a vault secret of the data with the given KbsClient. The
    /// data will be stored inside the vault with name `name`.
    pub async fn seal_with_kbs(
        _name: String,
        _data: Vec<u8>,
        _sealer: Arc<Mutex<KbsClient>>,
    ) -> Result<Self> {
        todo!()
    }

    /// Create a vault secret of the data with the given KbsClient. The
    /// data will be stored inside the vault with name `name`.
    pub async fn seal_with_kms(
        name: String,
        data: Vec<u8>,
        sealer: Arc<Mutex<dyn KMS>>,
    ) -> Result<Self> {
        let annotations = {
            let mut client = sealer.lock().await;
            client.set_secret(data, name.clone()).await?
        };

        Ok(Self { name, annotations })
    }
}
