// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

use base64::Engine;
use crypto::rust::{
    rsa::{PaddingMode, RSAKeyPair},
    traits::PublicKeyParts,
};
use kbs_types::TeePubKey;

pub struct TeeKeyPair {
    keypair: RSAKeyPair,
}

impl TeeKeyPair {
    pub fn new() -> Result<Self> {
        Ok(Self {
            keypair: RSAKeyPair::new()?,
        })
    }

    /// Export TEE public key as specific structure.
    pub fn export_pubkey(&self) -> Result<TeePubKey> {
        let engine = base64::engine::general_purpose::STANDARD;
        let k_mod = engine.encode(self.keypair.public_key.n().to_bytes_be());
        let k_exp = engine.encode(self.keypair.public_key.e().to_bytes_be());

        Ok(TeePubKey {
            alg: PaddingMode::PKCS1v15.as_ref().to_string(),
            k_mod,
            k_exp,
        })
    }

    #[inline]
    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        self.keypair.decrypt(mode, cipher_text)
    }
}
