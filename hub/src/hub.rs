// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, sync::Arc};

use anyhow::*;
use image::annotation_packet::{v2::Unwrapper, AnnotationPacket};
use kbs_client::Client as KbsClient;
use kms_client::KMS;
use resource_uri::ResourceUri;
use secret::{secret::Secret, unsealer::UnSealer};
use tokio::sync::Mutex;

pub struct DataHub {
    #[cfg(feature = "kms")]
    kms_manager: HashMap<String, Arc<Mutex<dyn KMS>>>,

    #[cfg(feature = "kbs")]
    kbs_client: Arc<Mutex<KbsClient>>,
}

impl DataHub {
    #[cfg(feature = "kbs")]
    pub async fn start(kbs_host_url: String) -> Result<Self> {
        // We should think about the given parameter here. Also, we
        // should think about how the `auth` layer runs.

        let kbs_client = KbsClient::new(kbs_host_url).await?;
        Ok(Self {
            kbs_client: Arc::new(Mutex::new(kbs_client)),

            #[cfg(feature = "kms")]
            kms_manager: HashMap::new(),
        })
    }

    pub async fn unseal_secret(&self, secret: Secret) -> Result<Vec<u8>> {
        #[cfg(feature = "kbs")]
        if secret.provider == "kbs" {
            let unsealer: UnSealer = self.kbs_client.clone().into();
            let plaintext = unsealer.unseal(secret).await?;
            return Ok(plaintext);
        }

        #[cfg(feature = "kms")]
        if !self.kms_manager.is_empty() {
            let driver = self.kms_manager.get(&secret.provider).ok_or_else(|| {
                anyhow!(
                    "No KMS driver named {} found to unseal the secret.",
                    secret.provider
                )
            })?;
            let unsealer = Into::<UnSealer>::into(driver.clone());
            let plaintext = unsealer.unseal(secret).await?;
            return Ok(plaintext);
        }

        bail!("Unseal failed!")
    }

    pub async fn unwrap_key(&self, annotation: &[u8]) -> Result<Vec<u8>> {
        let annotation_packet =
            serde_json::from_slice(annotation).context("parse AnnotationPacket failed")?;
        match annotation_packet {
            AnnotationPacket::V1(v1) => {
                cfg_if::cfg_if! {
                    if #[cfg(feature = "kbs")] {
                        v1.unwrap_key_with(self.kbs_client.clone()).await
                    } else {
                        bail!("Cannot unwrap key of a AnnotationV1 without kbs-client. Please enable feature `kbs` of hub.")
                    }
                }
            }
            AnnotationPacket::V2(v2) => {
                #[cfg(feature = "kbs")]
                if v2.provider == "kbs" {
                    let lek = v2
                        .unwrap_key_with(Unwrapper::Kbs(self.kbs_client.clone()))
                        .await?;
                    return Ok(lek);
                }

                #[cfg(feature = "kms")]
                if !self.kms_manager.is_empty() {
                    let driver = self.kms_manager.get(&v2.provider).ok_or_else(|| {
                        anyhow!(
                            "No KMS driver named {} found to unwrap the image's lek.",
                            v2.provider
                        )
                    })?;
                    let lek = v2.unwrap_key_with(Unwrapper::Kms(driver.clone())).await?;
                    return Ok(lek);
                }

                bail!("Unwrap failed!")
            }
        }
    }

    pub async fn get_resource(&self, uri: String) -> Result<Vec<u8>> {
        let resource_uri: ResourceUri =
            serde_json::from_str(&uri).context("parse resource URI failed")?;
        let resource = self
            .kbs_client
            .clone()
            .lock()
            .await
            .get_resource(resource_uri)
            .await?;
        Ok(resource)
    }
}
