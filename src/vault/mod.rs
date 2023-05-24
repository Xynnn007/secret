// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum VaultProvider {
    Ali,
}

#[derive(Serialize, Deserialize)]
pub struct VaultSecret {
    pub provider: VaultProvider,
    pub annotations: HashMap<String, String>,
}
