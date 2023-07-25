// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() -> std::io::Result<()> {
    tonic_build::compile_protos("../../protos/attestation-agent.proto")?;

    Ok(())
}
