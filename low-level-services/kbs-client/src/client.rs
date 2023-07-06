// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use kbs_protocol::client::{Handshaker, KBS_URL_PREFIX};
use kbs_types::Response;
use resource_uri::ResourceUri;

pub struct Client {
    handshaker: Handshaker,
    kbs_host_url: String,
}

impl Client {
    pub async fn new(kbs_host_url: String) -> Result<Self> {
        let mut handshaker = Handshaker::new().await?;
        handshaker.handshake(&kbs_host_url).await?;
        Ok(Self {
            handshaker,
            kbs_host_url,
        })
    }

    pub async fn new_with_handshaker(
        mut handshaker: Handshaker,
        kbs_host_url: String,
    ) -> Result<Self> {
        handshaker.handshake(&kbs_host_url).await?;
        Ok(Self {
            handshaker,
            kbs_host_url,
        })
    }

    /// Get the resource of the given KBS Resource URI.
    /// We need to change the API when it is time to support multiple KBSes.
    pub async fn get_resource(&self, resource_url: &ResourceUri) -> Result<Vec<u8>> {
        let url = format!(
            "{}/{KBS_URL_PREFIX}/{}",
            self.kbs_host_url,
            resource_url.resource_path()
        );

        let res = self.handshaker.http_client.get(url).send().await?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let response = res.json::<Response>().await?;
                let payload_data = self.handshaker.decrypt_response(response)?;
                Ok(payload_data)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                bail!("Unauthorized request.")
            }
            reqwest::StatusCode::NOT_FOUND => {
                bail!("KBS resource Not Found (Error 404)")
            }
            _ => {
                bail!(
                    "KBS Server Internal Failed, Response: {:?}",
                    res.text().await?
                )
            }
        }
    }
}
