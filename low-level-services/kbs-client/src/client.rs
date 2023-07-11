// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use kbs_protocol::client::Handshaker;
use resource_uri::ResourceUri;

pub struct Client {
    handshaker: Handshaker,
    _token: String,
}

impl Client {
    pub async fn new(kbs_host_url: String) -> Result<Self> {
        let mut handshaker = Handshaker::new().await?;
        let _token = handshaker.handshake(kbs_host_url).await?;
        Ok(Self { handshaker, _token })
    }

    pub async fn new_with_handshaker(
        mut handshaker: Handshaker,
        kbs_host_url: String,
    ) -> Result<Self> {
        let _token = handshaker.handshake(kbs_host_url).await?;
        Ok(Self { handshaker, _token })
    }

    /// Get the resource of the given KBS Resource URI.
    /// We need to change the API when it is time to support multiple KBSes.
    pub async fn get_resource(&mut self, resource_url: ResourceUri) -> Result<Vec<u8>> {
        self.handshaker.get(resource_url, true).await
    }
}
