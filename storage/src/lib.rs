// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod ali;

use std::sync::Arc;

use anyhow::*;
use async_trait::async_trait;
use strum::{AsRefStr, EnumString};
use tokio::sync::Mutex;

#[derive(AsRefStr, EnumString, Hash, Eq, PartialEq, Clone)]
pub enum Type {
    AliOSS,
}

impl Type {
    pub fn to_client(&self) -> Result<Arc<Mutex<dyn Provider>>> {
        match self {
            Type::AliOSS => Ok(Arc::new(Mutex::new(ali::Client::from_env()?))),
        }
    }
}

#[async_trait]
pub trait Provider {
    fn from_env() -> Result<Self>
    where
        Self: Sized;
    async fn get_blob(&mut self, path: &str) -> Result<Vec<u8>>;
}
