// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use base64::Engine;
use rand::Rng;

pub fn generate_annotation() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut symmetric_iv = [0u8; 12];
    rand::thread_rng().fill(&mut symmetric_iv);
    let iv = base64::engine::general_purpose::STANDARD.encode(symmetric_iv);
    map.insert("iv".to_string(), iv);
    map
}
