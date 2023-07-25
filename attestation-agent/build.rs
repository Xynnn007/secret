// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "ttrpc")]
use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

fn main() -> std::io::Result<()> {
    #[cfg(feature = "grpc")]
    {
        tonic_build::compile_protos("../protos/attestation-agent.proto")?;
    }

    Ok(())
}
