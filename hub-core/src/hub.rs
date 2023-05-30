// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::storage::StorageManager;

use anyhow::*;
use secret::secret::Secret;

#[derive(Default)]
pub struct DataHub {
    storage_mgr: StorageManager,
}

impl DataHub {
    pub fn new() -> Self {
        Self {
            storage_mgr: StorageManager::default()
        }
    }

    pub async fn get_blob(&mut self, provider: &str, path: &str) -> Result<Vec<u8>> {
        self.storage_mgr.get_blob(provider, path).await
    }

    pub async fn open_secret(&mut self, secret: &str) -> Result<Vec<u8>> {
        let secret: Secret = serde_json::from_str(secret)?;
        secret.open().await
    }
}
