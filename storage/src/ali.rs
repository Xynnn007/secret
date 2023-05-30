// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Aliyun OSS Client implementation
//!
//! To init a client we need the env to include the following key-values
//!
//! - "ALIYUN_KEY_ID"
//! - "ALIYUN_KEY_SECRET"
//! - "ALIYUN_ENDPOINT"
//! - "ALIYUN_BUCKET"

use std::env;

use aliyun_oss_client::{file::Files, BucketName, ObjectPath};
use anyhow::*;
use async_trait::async_trait;

use crate::Provider;

pub const ALIYUN_KEY_ID: &str = "ALIYUN_KEY_ID";
pub const ALIYUN_KEY_SECRET: &str = "ALIYUN_KEY_SECRET";
pub const ALIYUN_ENDPOINT: &str = "ALIYUN_ENDPOINT";
pub const ALIYUN_BUCKET: &str = "ALIYUN_BUCKET";

pub struct Client {
    inner: aliyun_oss_client::Client,
}

#[async_trait]
impl Provider for Client {
    fn from_env() -> Result<Self>
    where
        Self: Sized,
    {
        let key = env::var(ALIYUN_KEY_ID)?;
        let secret = env::var(ALIYUN_KEY_SECRET)?;
        let endpoint = env::var(ALIYUN_ENDPOINT)?;
        let bucket = env::var(ALIYUN_BUCKET)?;
        let bucket = BucketName::new(bucket.clone())?;

        let inner =
            aliyun_oss_client::Client::new(key.into(), secret.into(), endpoint.try_into()?, bucket);

        Ok(Self { inner })
    }

    async fn get_blob(&mut self, path: &str) -> Result<Vec<u8>> {
        let path: ObjectPath = path.parse()?;
        let blob = self.inner.get_object(path, ..).await?;
        Ok(blob)
    }
}
