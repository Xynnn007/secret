// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::Engine;
use clap::Parser;
use kms::kms::KMSEnum;
use secret::{
    envelope::Envelope,
    secret::{Secret, SecretType},
};

#[derive(Parser)] // requires `derive` feature
#[command(name = "secret")]
#[command(bin_name = "secret")]
#[command(author, version, about, long_about = None)]
enum Cli {
    Seal(SealArgs),
    Unseal(UnsealArgs),
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
struct UnsealArgs {
    /// blob of the secret
    #[arg(short, long)]
    blob: String,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
struct SealArgs {
    /// blob of the secret with base64 encoded
    #[arg(short, long)]
    blob: String,

    /// key id from KMS used to seal
    #[arg(short, long)]
    keyid: String,

    /// KMS used to seal the secret. Currently only ali is supproted
    #[arg(short, long)]
    kms: KMSEnum,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    match args {
        Cli::Unseal(para) => {
            let secret: Secret = serde_json::from_str(&para.blob)?;
            let content = secret.open().await?;
            let base64encoded = base64::engine::general_purpose::STANDARD.encode(content);
            println!("{base64encoded}");
        }
        Cli::Seal(para) => {
            let blob = base64::engine::general_purpose::STANDARD.decode(&para.blob)?;
            let envelope = Envelope::seal(para.kms, para.keyid, blob).await?;
            let secret = Secret {
                version: "0.1.0".into(),
                r#type: SecretType::KMS(envelope),
            };
            let res_str = serde_json::to_string(&secret)?;
            println!("{res_str}");
        }
    }

    Ok(())
}
