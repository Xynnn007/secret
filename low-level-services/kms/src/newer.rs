// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::*;
use strum::EnumString;

use crate::{Decryptor, Annotations};

#[derive(EnumString)]
pub enum Kms {
    Ali
}

impl Kms {
    pub async fn new_decryptor(name: &str, annotations: Annotations) -> Result<Arc<dyn Decryptor>> {
        let kms = Kms::try_from(name)?;
        match kms {
            Kms::Ali => {
                let client = crate::ali::Client::new(&annotations).await?;
                Ok(client)
            }
        }
    }
}