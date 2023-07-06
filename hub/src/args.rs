// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The socket address to listen to
    #[arg(short, long)]
    pub socket: SocketAddr,

    /// KBS endpoint to connect to
    #[arg(short, long)]
    pub kbs_addr: String,
}
