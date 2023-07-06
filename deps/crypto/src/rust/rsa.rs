// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Implementations of the TeeKey

use anyhow::*;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

const RSA_PUBKEY_LENGTH: usize = 2048;

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

/// Definations of different Padding mode for encryption. Refer to
/// <https://datatracker.ietf.org/doc/html/rfc7518#section-4.1> for
/// more information.
#[derive(EnumString, AsRefStr)]
pub enum PaddingMode {
    #[strum(serialize = "RSA-OAEP")]
    OAEP,

    #[strum(serialize = "RSA1_5")]
    PKCS1v15,
}

impl RSAKeyPair {
    pub fn new() -> Result<RSAKeyPair> {
        let mut rng = rand::thread_rng();

        let private_key = RsaPrivateKey::new(&mut rng, RSA_PUBKEY_LENGTH)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(RSAKeyPair {
            private_key,
            public_key,
        })
    }

    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        match mode {
            PaddingMode::OAEP => self
                .private_key
                .decrypt(Oaep::new::<sha2::Sha256>(), &cipher_text)
                .map_err(|e| anyhow!("RSA key decrypt OAEP failed: {:?}", e)),
            PaddingMode::PKCS1v15 => self
                .private_key
                .decrypt(Pkcs1v15Encrypt, &cipher_text)
                .map_err(|e| anyhow!("RSA key pkcs1v15 decrypt failed: {:?}", e)),
        }
    }
}
