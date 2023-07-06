// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod message;

use std::sync::Arc;

use anyhow::*;
use log::{debug, error};
use tonic::{Request, Response, Status};

use crate::service::{
    services::keyprovider::message::{KeyProviderInput, KeyUnwrapOutput, KeyUnwrapResults},
    Server,
};

use self::keyprovider_proto::{
    key_provider_service_server::KeyProviderService, KeyProviderKeyWrapProtocolInput,
    KeyProviderKeyWrapProtocolOutput,
};

pub mod keyprovider_proto {
    tonic::include_proto!("keyprovider");
}

#[tonic::async_trait]
impl KeyProviderService for Arc<Server> {
    async fn wrap_key(
        &self,
        _request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The WrapKey API is called...");
        debug!("WrapKey API is unimplemented!");
        Err(Status::unimplemented(
            "WrapKey API is unimplemented!".to_string(),
        ))
    }

    async fn un_wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The UnWrapKey API is called...");

        // Deserialize and parse the gRPC input to get KBC name, KBS URI and annotation.
        let key_provider_input: KeyProviderInput =
            serde_json::from_slice(&request.into_inner().key_provider_key_wrap_protocol_input)
                .map_err(|e| {
                    error!("Parse request failed: {}", e);
                    Status::internal(format!("[ERROR] Parse request failed: {e}",))
                })?;

        debug!("Call CDH to decrypt...");

        let annotation = key_provider_input.get_annotation().map_err(|e| {
            error!("Parse request failed: {}", e);
            Status::internal(format!("[ERROR] Parse request failed: {e}",))
        })?;

        let decrypted_optsdata = self.core.unwrap_key(&annotation).await.map_err(|e| {
            error!("Call CDH to provide key failed: {}", e);
            Status::internal(format!("[ERROR] CDH key provider failed: {e}",))
        })?;

        debug!("Provide key successfully, get the plain PLBCO");

        // Construct output structure and serialize it as the return value of gRPC
        let output_struct = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults {
                optsdata: decrypted_optsdata,
            },
        };

        let output = serde_json::to_string(&output_struct)
            .unwrap()
            .as_bytes()
            .to_vec();

        debug!(
            "UnWrapKey API output: {}",
            serde_json::to_string(&output_struct).unwrap()
        );

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Result::Ok(Response::new(reply))
    }
}
