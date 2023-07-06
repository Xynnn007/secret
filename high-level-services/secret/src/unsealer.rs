// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::*;
use kbs_client::Client as KbsClient;
use kms::KMS;
use tokio::sync::Mutex;

use crate::secret::{Secret, SecretContent};

pub enum UnSealer {
    Kms(Arc<Mutex<dyn KMS>>),
    Kbs(Arc<Mutex<KbsClient>>),
}

impl From<Arc<Mutex<dyn KMS>>> for UnSealer {
    fn from(value: Arc<Mutex<dyn KMS>>) -> Self {
        Self::Kms(value)
    }
}

impl From<Arc<Mutex<KbsClient>>> for UnSealer {
    fn from(value: Arc<Mutex<KbsClient>>) -> Self {
        Self::Kbs(value)
    }
}

impl UnSealer {
    pub async fn unseal(&self, secret: Secret) -> Result<Vec<u8>> {
        match secret.r#type {
            SecretContent::Envelope(envelope) => match self {
                UnSealer::Kms(k) => envelope.unseal_with_kms(k.clone()).await,
                UnSealer::Kbs(k) => envelope.unseal_with_kbs(k.clone()).await,
            },
            SecretContent::Vault(vault) => match self {
                UnSealer::Kms(k) => vault.unseal_with_kms(k.clone()).await,
                UnSealer::Kbs(k) => vault.unseal_with_kbs(k.clone()).await,
            },
        }
    }
}
