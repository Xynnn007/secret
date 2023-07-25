// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

mod aa {
    tonic::include_proto!("attestation_agent");
}

pub struct Server {
    tee: String,
}

impl Server {
    pub fn new() -> Self {
        let tee = attester::detect_tee_type();
    }
}