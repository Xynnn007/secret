// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;

#[async_trait]
pub trait Provider: Send + Sync {
    async fn get_blob(&mut self, path: &str) -> Result<Vec<u8>>;
}
