// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod keyprovider;

use hub_core::DataHub;

mod get_resource {
    tonic::include_proto!("keyprovider");
}

#[derive(Default)]
pub struct Service {
    core: DataHub,
}