// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::*;
use base64::Engine;
use clap::Parser;
use kbs_client::Client as KbsClient;
use secret::{
    secret::{
        layout::{envelope::Envelope, vault::VaultSecret},
        SealType, Secret, SecretContent,
    },
    unsealer::UnSealer,
};
use tokio::sync::Mutex;

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

    /// Address of the KBS, e.g. `http://example-kbs.io`. Used when the
    /// secret is sealed by a KBS.
    #[arg(short, long)]
    kbs_addr: Option<String>,
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

    /// KMS name or `kbs`, used to seal the secret.
    #[arg(short, long)]
    provider: String,

    /// Address of the KBS, e.g. `http://example-kbs.io`. Used when the
    /// secret is sealed by a KBS.
    #[arg(short, long)]
    kbs_addr: Option<String>,

    /// Type of the Secret, i.e. `vault` or `envelope`
    #[arg(short, long)]
    r#type: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    match args {
        Cli::Unseal(para) => {
            let secret: Secret = serde_json::from_str(&para.blob)?;
            let client = get_unsealer(secret.provider.clone(), para.kbs_addr).await?;
            let content = client.unseal(secret).await?;
            let base64encoded = base64::engine::general_purpose::STANDARD.encode(content);
            println!("{base64encoded}");
        }
        Cli::Seal(para) => {
            let blob = base64::engine::general_purpose::STANDARD.decode(&para.blob)?;
            let typ = SealType::try_from(&para.r#type[..])?;
            let secret = seal(para.provider, para.keyid, para.kbs_addr, typ, blob).await?;
            let res_str = serde_json::to_string_pretty(&secret)?;
            println!("{res_str}");
        }
    }

    Ok(())
}

const KBS_PROVIDER_NAME: &str = "kbs";
const VERSION: &str = "0.1.0";

async fn seal(
    provider: String,
    kid: String,
    kbs_addr: Option<String>,
    typ: SealType,
    data: Vec<u8>,
) -> Result<Secret> {
    if provider == KBS_PROVIDER_NAME {
        let kbs_addr = kbs_addr.ok_or_else(|| {
            anyhow!("If kbs is used to seal secret, `kbs_addr` parameter must be given!")
        })?;
        let client = Arc::new(Mutex::new(KbsClient::new(kbs_addr).await?));

        match typ {
            SealType::Envelope => {
                let e = Envelope::seal_with_kbs(kid, data, client).await?;
                Ok(Secret {
                    version: VERSION.into(),
                    provider,
                    r#type: SecretContent::Envelope(e),
                })
            }
            SealType::Vault => {
                let v = VaultSecret::seal_with_kbs(kid, data, client).await?;
                Ok(Secret {
                    version: VERSION.into(),
                    provider,
                    r#type: SecretContent::Vault(v),
                })
            }
        }
    } else {
        // We need to impl KMS client init here
        // let e = Envelope::seal_with_kms(name, data, k.clone()).await?;
        // Ok(Secret {
        //     version: VERSION.into(),
        //     provider,
        //     r#type: SecretType::Envelope(e),
        // })
        todo!()
    }
}

async fn get_unsealer(provider: String, kbs_addr: Option<String>) -> Result<UnSealer> {
    if provider == "kbs" {
        let kbs_addr = kbs_addr.ok_or_else(|| {
            anyhow!("If kbs is used to seal secret, `kbs_addr` parameter must be given!")
        })?;
        let client = Arc::new(Mutex::new(KbsClient::new(kbs_addr).await?));
        Ok(client.into())
    } else {
        todo!()
    }
}
