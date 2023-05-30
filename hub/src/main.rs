// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::SocketAddr;

use clap::Parser;

mod service;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The socket address to listen to
    #[arg(short, long)]
    socket: SocketAddr,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    
}
