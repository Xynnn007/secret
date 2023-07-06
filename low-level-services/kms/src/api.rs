// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Drivers of KMS

use std::collections::HashMap;

use anyhow::{bail, Result};
use async_trait::async_trait;

/// Annotations is extra information of this encryption/decryption.
/// Because the fields are unknowned, we put them into a key-value map.
type Annotations = HashMap<String, String>;

#[async_trait]
pub trait KMS: Send + Sync {
    /// The name of this KMS.
    fn name(&self) -> &str;

    /// Use the key of `keyid` to encrypt the `data` slice inside KMS, and then
    /// return the ciphertext of the `data`. The encryption operation should occur
    /// inside KMS. This function only works as a wrapper for different KMS APIs.
    ///
    /// Extra parameters can be included in `annotations`.
    async fn encrypt(&mut self, _data: &[u8], _keyid: &str) -> Result<(Vec<u8>, Annotations)> {
        bail!("Unimplemented!")
    }

    /// Use the key of `keyid` to decrypt the `ciphertext` slice inside KMS, and then
    /// return the plaintext of the `data`. The decryption operation should occur
    /// inside KMS. This function only works as a wrapper for different KMS APIs
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        keyid: &str,
        annotations: &Annotations,
    ) -> Result<Vec<u8>>;

    /// Get secret. Different secret manager will use different parameters inside
    /// `annotations`.
    async fn get_secret(&mut self, name: &str, annotations: &Annotations) -> Result<Vec<u8>>;

    /// Set secret. The information to specify the identity of the
    /// secret is included in the `annotations`
    async fn set_secret(&mut self, _content: Vec<u8>, _name: String) -> Result<Annotations> {
        bail!("Unimplemented!")
    }
}
