// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use kms::vault::VaultEnum;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VaultSecret {
    pub provider: VaultEnum,
    pub annotations: HashMap<String, String>,
}

impl VaultSecret {
    pub async fn open(&self) -> Result<Vec<u8>> {
        let mut client = self.provider.to_client().await?;
        client.get_secret(&self.annotations).await
    }
}
