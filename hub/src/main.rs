// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

use clap::Parser;
use log::{error, info};
use service::Server;

pub mod args;
pub mod service;

pub use args::*;

#[tokio::main]
async fn main() {
    match real_main().await {
        std::result::Result::Ok(_) => {
            info!("exit.");
            std::process::exit(0);
        }
        Err(e) => {
            error!("Exit because of error {e}");
        }
    }
}

async fn real_main() -> Result<()> {
    let args = Args::parse();

    let server = Server::new(args).await?;
    server.serve().await
}
