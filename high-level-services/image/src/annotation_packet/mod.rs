// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

use self::{v1::AnnotationPacketV1, v2::AnnotationPacketV2};

pub mod v1;
pub mod v2;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnnotationPacket {
    /// Legacy format of AnnotationPacket, aiming to be decrypted by KBS
    V1(AnnotationPacketV1),

    /// New format of AnnotationPacket, aiming to support not only KBS
    /// but also different kinds of KMS.
    V2(AnnotationPacketV2),
}
