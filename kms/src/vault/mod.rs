// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Drivers of secret manager/vault like.

use std::collections::HashMap;

use anyhow::{bail, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use strum::EnumString;

#[async_trait]
pub trait Vault: Send {
    /// Get secret. Different secret manager will use different parameters inside
    /// `annotations`.
    async fn get_secret(&mut self, annotations: &HashMap<String, String>) -> Result<Vec<u8>>;

    /// Set secret. The information to specify the identity of the
    /// secret is included in the `annotations`
    async fn set_secret(
        &mut self,
        _content: Vec<u8>,
        _annotations: &HashMap<String, String>,
    ) -> Result<()> {
        bail!("Unimplemented!")
    }
}

/// An Enum of all the supported Secret Manager
#[derive(EnumString, Serialize, Deserialize)]
pub enum VaultEnum {
    Ali,
}

impl VaultEnum {
    pub async fn to_client(&self) -> Result<Box<dyn Vault>> {
        match self {
            VaultEnum::Ali => todo!(),
        }
    }
}
