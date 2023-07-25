// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]

use clap::{App, Arg};

mod server;

#[tokio::main]
async fn main() {
    env_logger::init();
    
}
