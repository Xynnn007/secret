// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::*;
use async_trait::async_trait;

use crate::{Decryptor, Annotations};

pub struct Client {}

#[async_trait]
impl Decryptor for Client {
    /// The `annotations` is a HashMap<String, String>. It should include all
    /// public parameters required to init a Decryptor KMS Client. The public
    /// parameters MAY including the following:
    /// - Region Id
    /// - Instance Id
    /// 
    /// This means that the private parameters, like the credential to access
    /// the KMS should be read inside the this function. We strongly recommend
    /// to read the credential file from a file path. In this way, KMS client
    /// can work together with the auth protocol. That means the KMS client can
    /// init itself in the following steps:
    /// 1. auth protocol passes remote attestation, and get the credential for
    /// the KMS client.
    /// 2. KMS client read the specified credential file to initialize itself. If
    /// no credential file exists, raise an error.
    async fn new(annotations: &Annotations) -> Result<Arc<Self>> {
        Ok(Arc::new(Self{}))
    }

    /// Use the key of `keyid` to decrypt the `ciphertext` slice inside KMS, and then
    /// return the plaintext of the `data`. The decryption operation should occur
    /// inside KMS. This function only works as a wrapper for different KMS APIs
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        keyid: &str,
    ) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    /// Get secret. Different secret manager will use different parameters inside
    /// `annotations`.
    async fn get_secret(&mut self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}